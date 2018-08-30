
"""
KCP protocol, just for fun
"""

__all__ = ("KCP", )

from time import time
from binascii import hexlify
from struct import pack, unpack

IKCP_RTO_NDL = 30 # no delay min rto
IKCP_RTO_MIN = 100 # normal min rto
IKCP_RTO_DEF = 200
IKCP_RTO_MAX = 60000

IKCP_CMD_PUSH = 81 # cmd: push data
IKCP_CMD_ACK = 82 # cmd: ack
IKCP_CMD_WASK = 83 # cmd: window probe (ask)
IKCP_CMD_WINS = 84 # cmd: window size (tell)

IKCP_ASK_SEND = 1 # need to send IKCP_CMD_WASK
IKCP_ASK_TELL = 2 # need to send IKCP_CMD_WINS

IKCP_WND_SND = 32
IKCP_WND_RCV = 128 # must >= max fragment size
IKCP_MTU_DEF = 1400

IKCP_ACK_FAST = 3
IKCP_INTERVAL = 100

IKCP_OVERHEAD = 24
IKCP_DEADLINK = 20

IKCP_THRESH_INIT = 2
IKCP_THRESH_MIN = 2

IKCP_PROBE_INIT = 7000 # 7 secs to probe window size
IKCP_PROBE_LIMIT = 120000 # up to 120 secs to probe window

def log(fmt, *args):
    pass

def clock():
    return int(time() * 1000) & 0xffffffff

def u(n):
    if n > 0xffffffff:
        return 0
    return n

def diff(a, b):
    d = a - b
    if d > 0x7fffffff:
        return d - 0xffffffff - 1
    return d

def bound(lower, middle, upper):
    return min(max(lower, middle), upper)

class Segment(object):

    __slots__ = ("conv", "cmd", "frg", "wnd", "ts", "sn", "una", "len", "data", 
            "resendts", "rto", "fastack", "xmit")

    def __str__(self):
        return "Segment(%s, %s)" % (self.sn, hexlify(self.data))

    def __repr__(self):
        return "Segment(%s, %s)" % (self.sn, hexlify(self.data))

class KCP(object):

    def __init__(self, conv, output = None, nodelay = False, fastresend = 0, 
            mtu = IKCP_MTU_DEF, stream = False, interval = IKCP_INTERVAL, 
            nocwnd = False, snd_wnd = IKCP_WND_SND, rcv_wnd = IKCP_WND_RCV, log = None):
        self.conv = conv

        self.snd_una = 0
        self.snd_nxt = 0
        self.rcv_nxt = 0

        self.ts_probe = 0
        self.probe_wait = 0

        self.snd_wnd = snd_wnd
        self.rcv_wnd = rcv_wnd
        self.rmt_wnd = IKCP_WND_RCV
        self.cwnd = 0

        self.incr = 0
        self.probe = 0

        self.mtu = mtu
        self.mss = mtu - IKCP_OVERHEAD
        self.stream = stream

        self.buffer = []
        self.buffer_length = 0
        self.snd_queue = []
        self.rcv_queue = []
        self.snd_buf = []
        self.rcv_buf = []

        self.state = 0
        self.acklist = []

        self.rx_srtt = 0
        self.rx_rttval = 0
        self.rx_rto = IKCP_RTO_DEF
        self.rx_minrto = IKCP_RTO_MIN

        self.current = 0
        self.updated = False
        self.update_immediately = False

        self.interval = interval
        self.ts_flush = IKCP_INTERVAL
        self.ssthresh = IKCP_THRESH_INIT

        self.fastresend = fastresend
        self.nodelay = nodelay
        self.nocwnd = nocwnd

        self.xmit = 0
        self.dead_link = IKCP_DEADLINK

        self.log = log
        self.output = output

    def __str__(self):
        try:
            return self.name
        except AttributeError:
            return "%s(%s)" % (self.__class__.__name__, id(self))

    def __repr__(self):
        try:
            return self.name
        except AttributeError:
            return "%s(%s)" % (self.__class__.__name__, id(self))

    # config setter
    #=========================================================================
    def set_interval(self, interval):
        if self.log: self.log("%s set_interval %s", self, interval)
        if interval > 5000:
            interval = 5000
        elif interval < 10:
            interval = 10
        self.interval = interval

    def set_mtu(self, mtu):
        if self.log: self.log("%s set_mtu %s", self, mtu)
        if mut < 50 or mut < IKCP_OVERHEAD:
            return False
        self.mtu = mtu
        self.mss = self.mtu - IKCP_OVERHEAD
        self.buffer = []
        return True

    def set_nodelay(self, nodelay, interval, resend, nocwnd):
        if self.log: self.log("%s set_nodelay %s %s %s", self, nodelay, interval, resend, nocwnd)
        self.nodelay = nodelay
        if nodelay:
            self.rx_minrto = IKCP_RTO_NDL
        else:
            self.rx_minrto = IKCP_RTO_MIN

        self.set_interval(interval)
        if resend > 0:
            self.fastresend = resend
        if nocwnd:
            self.nocwnd = nocwnd

    def set_wndsize(self, snd_wnd, rcv_wnd):
        if self.log: self.log("%s set_wndsize %s %s", self, snd_wnd, rcv_wnd)
        self.snd_wnd = snd_wnd
        self.rcv_wnd = rcv_wnd

    # private 
    #=========================================================================
    def wait_snd(self):
        return len(self.snd_queue) + len(self.snd_buf)

    def wnd_unused(self):
        unuse = self.rcv_wnd - len(self.rcv_queue)
        if unuse > 0:
            return unuse
        return 0

    def peek_size(self):
        rcv_queue = self.rcv_queue
        if not rcv_queue:
            return -1
        seg = rcv_queue[0]
        if seg.frg == 0:
            return seg.len
        if len(rcv_queue) < seg.frg + 1:
            return -1
        length = 0
        for seg in rcv_queue:
            length += seg.len
            if seg.frg == 0:
                break
        return length

    def update_ack(self, rtt):
        if self.rx_srtt == 0:
            self.rx_srtt = rtt
            self.rx_rttval = rtt / 2
        else:
            delta = rtt - self.rx_srtt
            if delta < 0:
                delta = -delta
            self.rx_rttval = (3 * self.rx_rttval + delta) / 4
            self.rx_srtt = (7 * self.rx_srtt + rtt) / 8
            if self.rx_srtt < 1:
                self.rx_srtt = 1

        rto = self.rx_srtt + max(self.interval, 4 * self.rx_rttval)
        self.rx_rto = bound(self.rx_minrto, rto, IKCP_RTO_MAX)

    def shrink_buf(self):
        snd_buf = self.snd_buf
        if snd_buf:
            self.snd_una = snd_buf[0].sn
        else:
            self.snd_una = self.snd_nxt
        if self.log: self.log("%s shrink_buf %s", self, self.snd_una)

    def parse_ack(self, sn):
        if diff(sn, self.snd_una) < 0 or diff(sn, self.snd_nxt) > 0:
            return 
        for index, seg in enumerate(self.snd_buf):
            if sn == seg.sn:
                if self.log: self.log("%s parse_ack pop %s %s", self, sn, index)
                self.snd_buf.pop(index)
                break
            if diff(sn, seg.sn) < 0:
                break

    def parse_una(self, una):
        snd_buf = self.snd_buf
        index = -1
        for index, seg in enumerate(snd_buf):
            if diff(una, seg.sn) <= 0:
                if index != 0:
                    if self.log: self.log("%s parse_una pop %s %s", self, una, [seg.sn for seg in snd_buf[:index]])
                    snd_buf[:index] = []
                break

    def parse_fastack(self, sn):
        if diff(sn, self.snd_una) < 0 or diff(sn, self.snd_nxt) > 0:
            return 
        for index, seg in enumerate(self.snd_buf):
            if diff(sn, seg.sn) < 0:
                break
            if sn != seg.sn:
                seg.fastack += 1 

    def parse_data(self, newseg):
        sn = newseg.sn

        if diff(sn, u(self.rcv_nxt + self.rcv_wnd)) >= 0 or diff(sn, self.rcv_nxt) < 0:
            if self.log: self.log("%s parse_data out of wnd %s %s %s", self, sn, self.rcv_nxt, self.rcv_wnd)
            return 

        repeat = False
        rcv_buf = self.rcv_buf
        rcv_queue = self.rcv_queue

        index = -1
        for index, seg in enumerate(rcv_buf):
            if seg.sn == sn:
                repeat = True
                break
            if diff(sn, seg.sn) < 0:
                rcv_buf.insert(index, newseg)
                break
        else:
            rcv_buf.append(newseg)

        while rcv_buf:
            seg = rcv_buf[0]
            if seg.sn == self.rcv_nxt and len(rcv_queue) < self.rcv_wnd:
                rcv_buf.pop(0)
                rcv_queue.append(seg)
                self.rcv_nxt = u(self.rcv_nxt + 1)
            else:
                break

        if self.log: self.log("%s parse_data %s %s %s", self, sn, repeat, self.rcv_nxt)

    # public 
    #=========================================================================
    def recv(self, length):
        recover = False

        if length > 0:
            ispeek = True
        else:
            length = -length
            ispeek = False

        rcv_queue = self.rcv_queue
        if not rcv_queue:
            return "", -1

        peeksize = self.peek_size()
        if peeksize < 0:
            return "", -2
        if peeksize > length:
            return "", -3
        if len(rcv_queue) >= self.rcv_wnd:
            recover = True

        data = []

        index = -1
        for index, seg in enumerate(rcv_queue):
            data.append(seg.data)
            if seg.frg == 0:
                break

        if ispeek:
            rcv_queue[:index+1] = []

        rcv_buf = self.rcv_buf
        while rcv_buf:
            seg = rcv_buf[0]
            if seg.sn == self.rcv_nxt and len(rcv_queue) < self.rcv_wnd:
                rcv_buf.pop(0)
                rcv_queue.append(seg)
            else:
                break

        if recover and len(rcv_queue) < self.rcv_wnd:
            self.probe |= IKCP_ASK_TELL

        data = "".join(data)
        if self.log: self.log("%s recv %s", self, hexlify(data))

        return data, 0

    def send(self, buffer):
        length = len(buffer)
        if length <= 0: 
            return -1

        mss = self.mss
        snd_queue = self.snd_queue
        if self.stream and snd_queue:
            old = snd_queue[-1]
            n = len(old.data)
            if n < mss:
                capacity = mss - n
                old.frg = 0
                old.len += capacity
                old.data += buffer[:capacity]
                if capacity == len(buffer):
                    return 0
                length -= capacity
                buffer = buffer[capacity:]

        if length <= mss:
            count = 1
        else:
            count = (length + mss - 1) / mss

        if count >= IKCP_WND_RCV:
            return -2

        offset = 0
        for index in range(count):
            size = length if length < mss else mss
            seg = Segment()
            seg.len = size
            seg.data = buffer[offset:offset + size]
            seg.frg = 0 if self.stream else count - index - 1
            snd_queue.append(seg)
            offset += size

        if self.log: self.log("%s send %s %s", self, hexlify(buffer), len(snd_queue))

        self.update_immediately = True

        return 0

    def input(self, data):
        if self.log: self.log("%s input %s", self, hexlify(data))

        size = len(data)
        if size < IKCP_OVERHEAD:
            return -1

        self.update_immediately = True

        offset = 0
        current = self.current

        maxack = 0
        flag = True

        overhead = IKCP_OVERHEAD
        old_snd_una = self.snd_una

        while True:

            if size < overhead:
                break

            conv, cmd, frg, wnd, ts, sn, una, length = unpack("!IBBHIIII", data[offset: offset + overhead])
            if self.log: self.log("%s input part %s", self, hexlify(data[offset: offset + overhead + length]))

            if size < length:
                return -2

            if cmd != IKCP_CMD_PUSH and cmd != IKCP_CMD_ACK and cmd != IKCP_CMD_WASK and cmd != IKCP_CMD_WINS:
                return -3

            self.rmt_wnd = wnd
            self.parse_una(una)
            self.shrink_buf()

            if cmd == IKCP_CMD_ACK:
                delta = diff(current, ts)
                if delta >= 0:
                    self.update_ack(delta)
                self.parse_ack(sn)
                self.shrink_buf()
                if flag:
                    if diff(sn, maxack) > 0:
                        maxack = sn
                else:
                    flag = True
                    maxack = sn

            elif cmd == IKCP_CMD_PUSH:
                if diff(sn, u(self.rcv_nxt + self.rcv_wnd)) < 0:
                    self.acklist.append((sn, ts))
                    if diff(sn, self.rcv_nxt) >= 0:
                        seg = Segment()
                        seg.conv = conv
                        seg.cmd = cmd
                        seg.frg = frg
                        seg.wnd = wnd
                        seg.ts = ts
                        seg.sn = sn
                        seg.una = una
                        seg.len = length
                        seg.data = data[offset + overhead: offset + overhead + length]
                        self.parse_data(seg)
                else:
                    if self.log: self.log("%s input discard %s %s %s", self, sn, self.rcv_nxt, self.rcv_wnd)

            elif cmd == IKCP_CMD_WASK:
                self.probe |= IKCP_ASK_TELL

            elif cmd == IKCP_CMD_WINS:
                pass

            else:
                return -1

            size -= overhead + length
            offset += overhead + length

        if flag:
            self.parse_fastack(maxack)

        if diff(self.snd_una, old_snd_una) > 0:
            if self.cwnd  < self.rmt_wnd:
                mss = self.mss
                if self.cwnd  < self.ssthresh:
                    self.cwnd += 1
                    self.incr += mss
                else:
                    if self.incr < mss:
                        self.incr = mss
                    self.incr += (mss * mss) / self.incr + (mss / 16)
                    if (self.cwnd + 1) * mss <= self.incr:
                        self.cwnd += 1
                    if self.cwnd > self.rmt_wnd:
                        self.cwnd = self.rmt_wnd
                        self.incr = self.rmt_wnd * mss

        return 0

    def flush(self):
        if not self.updated:
            return 

        current = self.current
        buffer = self.buffer
        snd_queue = self.snd_queue
        rcv_nxt = self.rcv_nxt

        seg = Segment()
        seg.conv = self.conv
        seg.cmd = IKCP_CMD_ACK
        seg.frg = 0
        seg.wnd = self.wnd_unused()
        seg.una = rcv_nxt
        seg.len = 0
        seg.sn = 0
        seg.ts = 0

        mtu = self.mtu
        overhead = IKCP_OVERHEAD

        # send ack 
        #---------------------------------------------------------------------
        for sn, ts in self.acklist:
            seg.sn, seg.ts = sn, ts
            if self.buffer_length + overhead > mtu:
                self.output("".join(self.buffer))
                buffer[:] = []
                self.buffer_length = 0
            self.buffer_length += overhead
            buffer.append(pack("!IBBHIIII", seg.conv, seg.cmd, seg.frg, seg.wnd, seg.ts, seg.sn, seg.una, seg.len))
        self.acklist = []

        # send probe 
        #---------------------------------------------------------------------
        if self.rmt_wnd == 0:
            if self.probe_wait == 0:
                self.probe_wait = IKCP_PROBE_INIT
                self.ts_probe = u(current + self.probe_wait)
            elif diff(current, self.ts_probe) >= 0:
                if self.probe_wait < IKCP_PROBE_INIT:
                    self.probe_wait = IKCP_PROBE_INIT
                self.probe_wait += self.probe_wait / 2
                if self.probe_wait > IKCP_PROBE_LIMIT:
                    self.probe_wait = IKCP_PROBE_LIMIT
                self.ts_probe = u(current + self.probe_wait)
                self.probe |= IKCP_ASK_SEND
        else:
            self.ts_probe = 0
            self.probe_wait = 0

        if self.probe & IKCP_ASK_SEND:
            seg.cmd = IKCP_CMD_WASK
            if self.buffer_length + overhead > mtu:
                self.output("".join(buffer))
                buffer[:] = []
                self.buffer_length = 0
            self.buffer_length += overhead
            buffer.append(pack("!BBHIIII", seg.cmd, seg.frg, seg.wnd, seg.ts, seg.sn, seg.una, seg.len))

        if self.probe & IKCP_ASK_TELL:
            seg.cmd = IKCP_CMD_WINS
            if self.buffer_length + overhead > mtu:
                self.output("".join(buffer))
                buffer[:] = []
                self.buffer_length = 0
            self.buffer_length += overhead
            buffer.append(pack("!BBHIIII", seg.cmd, seg.frg, seg.wnd, seg.ts, seg.sn, seg.una, seg.len))

        self.probe = 0

        # send push
        #---------------------------------------------------------------------
        cwnd = min(self.snd_wnd, self.rmt_wnd)
        if not self.nocwnd:
            cwnd = min(self.cwnd, cwnd)
        snd_max = u(self.snd_una + cwnd)
        while diff(self.snd_nxt, snd_max) < 0:
            if not snd_queue:
                break
            segment = snd_queue.pop(0)
            segment.conv = self.conv
            segment.cmd = IKCP_CMD_PUSH
            segment.wnd = seg.wnd
            segment.ts = current
            segment.sn = self.snd_nxt
            segment.una = rcv_nxt
            segment.resendts = current
            segment.rto = self.rx_rto
            segment.fastack = 0
            segment.xmit = 0
            self.snd_buf.append(segment)
            self.snd_nxt = u(self.snd_nxt + 1)

        resent = self.fastresend if self.fastresend > 0 else 0xffffffff
        rtomin = 0 if self.nodelay else self.rx_rto >> 3

        change = 0
        lost = False

        for segment in self.snd_buf:
            needsend = False
            if segment.xmit == 0:
                needsend = True
                segment.xmit += 1
                # segment.rto = self.rx_rto 
                segment.resendts = u(current + segment.rto + rtomin)

            elif diff(current, segment.resendts) >= 0:
                needsend = True
                self.xmit += 1
                segment.xmit += 1
                if self.nodelay:
                    segment.rto += self.rx_rto / 2
                else:
                    segment.rto += self.rx_rto
                segment.resendts = u(current + segment.rto)
                lost = True

            elif segment.fastack >= resent:
                needsend = True
                segment.xmit += 1
                segment.fastack = 0
                segment.resendts = u(current + segment.rto)
                assert(segment.rto >= 0)
                change += 1

            if self.log: self.log("%s flush push %s %s %s %s", self, segment.sn, needsend, segment.resendts, hexlify(segment.data))

            if needsend:
                segment.ts = current
                segment.wnd = seg.wnd
                segment.una = rcv_nxt

                if self.buffer_length + overhead + seg.len > mtu:
                    self.output("".join(buffer))
                    buffer[:] = []
                    self.buffer_length = 0
                seg = segment
                self.buffer_length += overhead + seg.len
                buffer.append(pack("!IBBHIIII", seg.conv, seg.cmd, seg.frg, seg.wnd, seg.ts, seg.sn, seg.una, seg.len))
                buffer.append(segment.data)

                if segment.xmit >= self.dead_link:
                    self.state = -1

        if self.buffer_length > 0:
            self.output("".join(buffer))
            self.buffer_length = 0
            buffer[:] = []

        # update ssthresh
        #---------------------------------------------------------------------
        if change > 0:
            inflight = self.snd_nxt - self.snd_una
            self.ssthresh = inflight / 2
            if self.ssthresh < IKCP_THRESH_MIN:
                self.ssthresh = IKCP_THRESH_MIN
            self.cwnd = self.ssthresh + resent
            self.incr = self.cwnd + self.mss

        if lost:
            self.ssthresh /= 2
            if self.ssthresh < IKCP_THRESH_MIN:
                self.ssthresh = IKCP_THRESH_MIN
            self.cwnd = 1
            self.incr = self.mss

        if self.cwnd < 1:
            self.cwnd = 1
            self.incr = self.mss

    def update(self, current):
        self.current = current

        if not self.updated:
            self.updated = True
            self.ts_flush = current

        slap = diff(current, self.ts_flush)
        if slap >= 10000 or slap < -10000:
            self.ts_flush = current
            slap = 0

        if slap >= 0:
            self.ts_flush = u(self.ts_flush + self.interval)
            if diff(current, self.ts_flush) >= 0:
                self.ts_flush = u(current + self.interval)

            self.flush()

    def check(self, current):
        tm_packet = 0x7fffffff
        ts_flush = self.ts_flush

        if not self.updated:
            return current

        delta = diff(current, ts_flush)
        if delta >= 10000 or delta < -10000:
            ts_flush = current
        if diff(current, ts_flush) >= 0:
            return current

        tm_flush = diff(ts_flush, current)
        for seg in self.snd_buf:
            d = diff(seg.resendts, current)
            if d <= 0:
                return current
            if d < tm_packet:
                tm_packet = diff

        if tm_packet < tm_flush:
            minimal = tm_packet
        else:
            minimal = tm_flush
        if minimal > self.interval:
            minimal = self.interval

        return u(current + minimal)

class Poll(object):

    def __init__(self):
        self.endpoints = {}

    def add(self, k):
        old = self.endpoints.pop(k, None)
        self.endpoints[k] = k.check(clock())
        return old

    def remove(self, k):
        return self.endpoints.pop(k, None)

    def tick(self):
        current = clock()
        endpoints = self.endpoints
        for k, st in endpoints.items():
            if k.update_immediately:
                k.flush()
                endpoints[k] = k.check(current)
                k.update_immediately = False
            elif diff(current, st) >= 0:
                k.update(current)
                endpoints[k] = k.check(current)

