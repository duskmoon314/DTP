// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::cmp;

use std::time::Duration;
use std::time::Instant;

use std::collections::BTreeMap;

use crate::Config;
// use crate::Error;
use crate::Result;

use crate::cc;
use crate::frame;
use crate::packet;
use crate::ranges;

use crate::path;
use std::collections::HashMap;

// Loss Recovery
const PACKET_THRESHOLD: u64 = 3;

const TIME_THRESHOLD: f64 = 9.0 / 8.0;

const GRANULARITY: Duration = Duration::from_millis(1);

const INITIAL_RTT: Duration = Duration::from_millis(10);

const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

#[derive(Clone, Debug)]
pub struct Sent {
    pub pkt_num: u64,

    pub frames: Vec<frame::Frame>,

    pub time: Instant,

    pub size: usize,

    pub ack_eliciting: bool,

    pub in_flight: bool,
}

pub struct Recovery {
    loss_detection_timer: Option<Instant>,

    pto_count: u32,

    time_of_last_sent_ack_eliciting_pkt: [Option<Instant>; packet::EPOCH_COUNT],

    largest_acked_pkt: [u64; packet::EPOCH_COUNT],

    largest_sent_pkt: [u64; packet::EPOCH_COUNT],

    latest_rtt: Duration,

    smoothed_rtt: Option<Duration>,

    rttvar: Duration,

    min_rtt: Duration,

    pub max_ack_delay: Duration,

    loss_time: [Option<Instant>; packet::EPOCH_COUNT],

    sent: [BTreeMap<u64, Sent>; packet::EPOCH_COUNT],

    pub lost: [Vec<frame::Frame>; packet::EPOCH_COUNT],

    pub acked: [Vec<frame::Frame>; packet::EPOCH_COUNT],

    pub lost_count: usize,

    pub loss_probes: [usize; packet::EPOCH_COUNT],

    pub cc: Box<dyn cc::CongestionControl>,

    app_limited: bool,
}

impl Recovery {
    pub fn new(config: &Config) -> Self {
        Recovery {
            loss_detection_timer: None,

            pto_count: 0,

            time_of_last_sent_ack_eliciting_pkt: [None; packet::EPOCH_COUNT],

            largest_acked_pkt: [std::u64::MAX; packet::EPOCH_COUNT],

            largest_sent_pkt: [0; packet::EPOCH_COUNT],

            latest_rtt: Duration::new(0, 0),

            smoothed_rtt: None,

            min_rtt: Duration::new(0, 0),

            rttvar: Duration::new(0, 0),

            max_ack_delay: Duration::from_millis(25),

            loss_time: [None; packet::EPOCH_COUNT],

            sent: [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()],

            lost: [Vec::new(), Vec::new(), Vec::new()],

            acked: [Vec::new(), Vec::new(), Vec::new()],

            lost_count: 0,

            loss_probes: [0; packet::EPOCH_COUNT],

            cc: cc::new_congestion_control(config.cc_algorithm),

            app_limited: false,
        }
    }

    pub fn on_packet_sent(
        &mut self, pkt: Sent, epoch: packet::Epoch, handshake_completed: bool,
        now: Instant, trace_id: &str,
    ) {
        let ack_eliciting = pkt.ack_eliciting;
        let in_flight = pkt.in_flight;
        let sent_bytes = pkt.size;

        self.largest_sent_pkt[epoch] =
            cmp::max(self.largest_sent_pkt[epoch], pkt.pkt_num);

        self.sent[epoch].insert(pkt.pkt_num, pkt);

        if in_flight {
            if ack_eliciting {
                self.time_of_last_sent_ack_eliciting_pkt[epoch] = Some(now);
            }

            self.app_limited =
                (self.cc.bytes_in_flight() + sent_bytes) + 1350 < self.cc.cwnd();
            trace!(
                "bytes_in_flight={}   sent_bytes={}   cwnd={}",
                self.cc.bytes_in_flight(),
                sent_bytes,
                self.cc.cwnd()
            );

            // OnPacketSentCC
            self.cc.on_packet_sent_cc(sent_bytes, trace_id);

            self.set_loss_detection_timer(handshake_completed);
        }

        trace!("{} {:?}", trace_id, self);
    }

    pub fn on_ack_received(
        &mut self, ranges: &ranges::RangeSet, ack_delay: u64,
        epoch: packet::Epoch, handshake_completed: bool, now: Instant,
        trace_id: &str, pkt_num_space: &mut packet::PktNumSpace,
        paths: &mut [path::Path; crate::PATH_NUM], path: usize,
    ) -> Result<()> {
        // let largest_acked = ranges.largest().unwrap();

        // // If the largest packet number acked exceeds any packet number we have
        // // sent, then the ACK is obviously invalid, so there's no need to
        // // continue further.
        // if largest_acked > self.largest_sent_pkt[epoch] {
        //     if cfg!(feature = "fuzzing") {
        //         return Ok(());
        //     }

        //     return Err(Error::InvalidPacket);
        // }

        // if self.largest_acked_pkt[epoch] == std::u64::MAX {
        //     self.largest_acked_pkt[epoch] = largest_acked;
        // } else {
        //     self.largest_acked_pkt[epoch] =
        //         cmp::max(self.largest_acked_pkt[epoch], largest_acked);
        // }

        // if let Some(pkt) = self.sent[epoch].get(&self.largest_acked_pkt[epoch])
        // {     if pkt.ack_eliciting {
        //         let latest_rtt = now - pkt.time;

        //         let ack_delay = if epoch == packet::EPOCH_APPLICATION {
        //             Duration::from_micros(ack_delay)
        //         } else {
        //             Duration::from_micros(0)
        //         };

        //         self.update_rtt(latest_rtt, ack_delay);
        //     }
        // }

        let mut has_newly_acked = false;
        let mut newly_acked = false;

        if newly_acked {
            return Ok(());
        }

        // Each path maintains its own largest_acked packet_number value
        let mut largest_acked_firstpath = 0;
        let mut largest_acked_subseqpath = 0;

        // Record whether an ACK frame acknowledges the packets sent on a certain
        // path.
        let mut ack_packet_on_firstpath: bool = false;
        let mut ack_packet_on_subseqpath: bool = false;

        // Processing acked packets in reverse order (from largest to smallest)
        // appears to be faster, possibly due to the BTreeMap implementation.
        for pn in ranges.flatten().rev() {
            let path_id = pkt_num_space.pkts_sent_with_pathid.get(&pn);

            let init: usize = 0;
            let subseq: usize = 1;

            if path_id == Some(&init) && !ack_packet_on_firstpath {
                ack_packet_on_firstpath = true;
                largest_acked_firstpath = pn;
                break;
            } else if path_id == Some(&subseq) && !ack_packet_on_subseqpath {
                ack_packet_on_subseqpath = true;
                largest_acked_subseqpath = pn;
                break;
            } else {
                info!("none starts");
                continue;
            }
            // If the acked packet number is lower than the lowest unacked
            // packet number it means that the packet is not newly
            // acked, so return early.
            //
            // Since we process acked packets from largest to lowest, this means
            // that as soon as we see an already-acked packet number
            // all following packet numbers will also be already
            // acked.
            // if let Some(lowest) = self.sent[epoch].values().nth(0) {
            //     if pn < lowest.pkt_num {
            //         break;
            //     }
            // }

            // let newly_acked = self.on_packet_acked(pn, epoch, trace_id);
            // has_newly_acked = cmp::max(has_newly_acked, newly_acked);

            // if newly_acked {
            //     trace!("{} packet newly acked {}", trace_id, pn);
            // }
        }

        // Update rtt of two paths
        // There are acked packets sent from the first path.
        if ack_packet_on_firstpath {
            // Get first path largest_acked_pkt
            if paths[0].recovery.largest_acked_pkt[epoch] == std::u64::MAX {
                paths[0].recovery.largest_acked_pkt[epoch] =
                    largest_acked_firstpath;
            } else {
                paths[0].recovery.largest_acked_pkt[epoch] = cmp::max(
                    paths[0].recovery.largest_acked_pkt[epoch],
                    largest_acked_firstpath,
                );
            }

            if let Some(pkt) = paths[0].recovery.sent[epoch]
                .get(&paths[0].recovery.largest_acked_pkt[epoch])
            {
                if pkt.ack_eliciting {
                    let latest_rtt = now - pkt.time;

                    let ack_delay = if epoch == packet::EPOCH_APPLICATION {
                        Duration::from_micros(ack_delay)
                    } else {
                        Duration::from_micros(0)
                    };
                    if path == 0 {
                        info!("*****Path 0 update rtt!****");
                        paths[0].recovery.update_rtt(latest_rtt, ack_delay); // rtt
                    }
                }
            }
        }

        // There are acked packets sent from the subseqent path.
        if ack_packet_on_subseqpath {
            // Get second path largest_acked_pkt
            if paths[1].recovery.largest_acked_pkt[epoch] == std::u64::MAX {
                paths[1].recovery.largest_acked_pkt[epoch] =
                    largest_acked_subseqpath;
            } else {
                paths[1].recovery.largest_acked_pkt[epoch] = cmp::max(
                    paths[1].recovery.largest_acked_pkt[epoch],
                    largest_acked_subseqpath,
                );
            }

            if let Some(pkt) = paths[1].recovery.sent[epoch]
                .get(&paths[1].recovery.largest_acked_pkt[epoch])
            {
                if pkt.ack_eliciting {
                    let latest_rtt = now - pkt.time;

                    let ack_delay = if epoch == packet::EPOCH_APPLICATION {
                        Duration::from_micros(ack_delay)
                    } else {
                        Duration::from_micros(0)
                    };
                    if path == 1 {
                        info!("*****Path 1 update rtt!****");
                        paths[1].recovery.update_rtt(latest_rtt, ack_delay); // rtt
                    }
                }
            }
        }

        let mut ack_num = 0;

        let mut all_pkt_acked_paths = vec![false; crate::PATH_NUM];
        for pn in ranges.flatten().rev() {
            if let Some(lowest_first) =
                paths[0].recovery.sent[epoch].values().nth(0)
            {
                if pn < lowest_first.pkt_num {
                    all_pkt_acked_paths[0] = true;
                }
            }
            if let Some(lowest_subseq) =
                paths[1].recovery.sent[epoch].values().nth(0)
            {
                if pn < lowest_subseq.pkt_num {
                    all_pkt_acked_paths[1] = true;
                }
            }
            if all_pkt_acked_paths[0] && path == 0 {
                break;
            }
            if all_pkt_acked_paths[1] && path == 1 {
                break;
            }

            let path_id = pkt_num_space.pkts_sent_with_pathid.get(&pn);

            info!("pathid {:?}", path_id);

            // TODO: Unstable way to compare
            let init: usize = 0;
            let subseq: usize = 1;

            if path_id == Some(&init) {
                info!("*******pn:{}, first path****************", pn);
                // ack_packet_on_firstpath = true;

                newly_acked =
                    paths[0].recovery.on_packet_acked(pn, epoch, trace_id);
                if newly_acked {
                    ack_num = ack_num + 1;
                }
                has_newly_acked = cmp::max(has_newly_acked, newly_acked);
            } else if path_id == Some(&subseq) {
                info!("*******pn:{}, subseq path****************", pn);
                // ack_packet_on_subseqpath = true;

                newly_acked =
                    paths[1].recovery.on_packet_acked(pn, epoch, trace_id);
                if newly_acked {
                    ack_num = ack_num + 1;
                }
                has_newly_acked = cmp::max(has_newly_acked, newly_acked);
            } else {
                newly_acked = false;
                continue;
            }

            if newly_acked {
                pkt_num_space.pkts_sent_with_pathid.remove(&pn);
                trace!("{} packet newly acked {}", trace_id, pn);
            }
        }

        info!("ack num {}", ack_num);
        if !has_newly_acked {
            return Ok(());
        }

        if ack_packet_on_firstpath {
            info!("***********Path 0 detect lost packet**********");
            paths[0].recovery.detect_lost_packets(
                epoch,
                now,
                trace_id,
                paths[0].pkts_num_with_seq.clone(),
            );

            paths[0].recovery.pto_count = 0;
            paths[0]
                .recovery
                .set_loss_detection_timer(handshake_completed);
        }

        if ack_packet_on_subseqpath {
            info!("***********Path 1 detect lost packet**********");
            paths[1].recovery.detect_lost_packets(
                epoch,
                now,
                trace_id,
                paths[1].pkts_num_with_seq.clone(),
            );

            paths[1].recovery.pto_count = 0;
            paths[1]
                .recovery
                .set_loss_detection_timer(handshake_completed);
        }

        // self.detect_lost_packets(epoch, now, trace_id);

        // self.pto_count = 0;

        // self.set_loss_detection_timer(handshake_completed);

        trace!("{} {:?}", trace_id, self);

        Ok(())
    }

    pub fn on_loss_detection_timeout(
        &mut self, handshake_completed: bool, now: Instant, trace_id: &str,
        pkts_num_with_seq: HashMap<u64, u64>,
    ) {
        let (earliest_loss_time, epoch) =
            self.earliest_loss_time(self.loss_time, handshake_completed);

        if earliest_loss_time.is_some() {
            info!("*********earliest_loss_time***********");
            self.detect_lost_packets(epoch, now, trace_id, pkts_num_with_seq);
            self.set_loss_detection_timer(handshake_completed);

            trace!("{} {:?}", trace_id, self);
            return;
        }

        // TODO: handle client without 1-RTT keys case.

        let (_, epoch) = self.earliest_loss_time(
            self.time_of_last_sent_ack_eliciting_pkt,
            handshake_completed,
        );

        self.loss_probes[epoch] = 2;

        self.pto_count += 1;
        info!("pto count {}", self.pto_count);

        self.set_loss_detection_timer(handshake_completed);

        trace!("{} {:?}", trace_id, self);
    }

    pub fn drop_unacked_data(&mut self, epoch: packet::Epoch) {
        info!("drop function");
        let mut unacked_bytes = 0;

        for p in self.sent[epoch].values_mut().filter(|p| p.in_flight) {
            unacked_bytes += p.size;
        }

        self.cc.decrease_bytes_in_flight(unacked_bytes);

        self.loss_time[epoch] = None;
        self.loss_probes[epoch] = 0;
        self.time_of_last_sent_ack_eliciting_pkt[epoch] = None;

        self.sent[epoch].clear();
        self.lost[epoch].clear();
        self.acked[epoch].clear();
    }

    pub fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    pub fn cwnd_available(&self) -> usize {
        // Ignore cwnd when sending probe packets.
        if self.loss_probes.iter().any(|&x| x > 0) {
            return std::usize::MAX;
        }
        info!("cwnd {} bif {}", self.cc.cwnd(), self.cc.bytes_in_flight());
        self.cc.cwnd().saturating_sub(self.cc.bytes_in_flight())
    }

    pub fn rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(INITIAL_RTT)
    }

    pub fn pto(&self) -> Duration {
        self.rtt() + cmp::max(self.rttvar * 4, GRANULARITY) + self.max_ack_delay
    }

    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        self.latest_rtt = latest_rtt;

        match self.smoothed_rtt {
            // First RTT sample.
            None => {
                self.min_rtt = latest_rtt;

                self.smoothed_rtt = Some(latest_rtt);
                info!("smoothed_rtt1 {:?}", self.smoothed_rtt);

                self.rttvar = latest_rtt / 2;
            },

            Some(srtt) => {
                self.min_rtt = cmp::min(self.min_rtt, latest_rtt);

                let ack_delay = cmp::min(self.max_ack_delay, ack_delay);

                // Adjust for ack delay if plausible.
                let adjusted_rtt = if latest_rtt > self.min_rtt + ack_delay {
                    latest_rtt - ack_delay
                } else {
                    latest_rtt
                };

                self.rttvar = self.rttvar.mul_f64(3.0 / 4.0) +
                    sub_abs(srtt, adjusted_rtt).mul_f64(1.0 / 4.0);

                self.smoothed_rtt = Some(
                    srtt.mul_f64(7.0 / 8.0) + adjusted_rtt.mul_f64(1.0 / 8.0),
                );
                info!("**smoothed_rtt:{:?}**", self.smoothed_rtt);
            },
        }
    }

    fn earliest_loss_time(
        &mut self, times: [Option<Instant>; packet::EPOCH_COUNT],
        handshake_completed: bool,
    ) -> (Option<Instant>, packet::Epoch) {
        let mut epoch = packet::EPOCH_INITIAL;
        let mut time = times[epoch];

        // Iterate over all packet number spaces starting from Handshake.
        #[allow(clippy::needless_range_loop)]
        for e in packet::EPOCH_HANDSHAKE..packet::EPOCH_COUNT {
            let new_time = times[e];

            if e == packet::EPOCH_APPLICATION && !handshake_completed {
                continue;
            }

            if new_time.is_some() && (time.is_none() || new_time < time) {
                time = new_time;
                epoch = e;
            }
        }

        (time, epoch)
    }

    fn set_loss_detection_timer(&mut self, handshake_completed: bool) {
        let (earliest_loss_time, _) =
            self.earliest_loss_time(self.loss_time, handshake_completed);

        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            self.loss_detection_timer = earliest_loss_time;
            info!("loss_detection_timer1 {:?}", self.loss_detection_timer);
            return;
        }

        if self.cc.bytes_in_flight() == 0 {
            // TODO: check if peer is awaiting address validation.
            self.loss_detection_timer = None;
            return;
        }

        // PTO timer.
        let timeout = match self.smoothed_rtt {
            None => INITIAL_RTT * 2,

            Some(_) => self.pto() * 2_u32.pow(self.pto_count),
        };

        info!("timeout {}", timeout.as_millis());

        let (sent_time, _) = self.earliest_loss_time(
            self.time_of_last_sent_ack_eliciting_pkt,
            handshake_completed,
        );

        if let Some(sent_time) = sent_time {
            self.loss_detection_timer = Some(sent_time + timeout);
            info!("loss_detection_timer2 {:?}", self.loss_detection_timer);
        }
    }

    fn detect_lost_packets(
        &mut self, epoch: packet::Epoch, now: Instant, trace_id: &str,
        pkts_num_with_seq: HashMap<u64, u64>,
    ) {
        let largest_acked = self.largest_acked_pkt[epoch];

        let mut lost_pkt: Vec<u64> = Vec::new();

        self.loss_time[epoch] = None;
        info!("set loss time none");

        let loss_delay =
            cmp::max(self.latest_rtt, self.rtt()).mul_f64(TIME_THRESHOLD);

        // Minimum time of kGranularity before packets are deemed lost.
        let loss_delay = cmp::max(loss_delay, GRANULARITY);

        // Packets sent before this time are deemed lost.
        let lost_send_time = now - loss_delay;

        for (_, unacked) in self.sent[epoch].range(..=largest_acked) {
            // Mark packet as lost, or set time when it should be marked.
            // if unacked.time <= lost_send_time ||
            //     largest_acked >= unacked.pkt_num + PACKET_THRESHOLD
            info!("lost_send_time {:?}", lost_send_time);
            info!("unacked.time {:?}", unacked.time);
            info!(
                "unacked.time <= lost_send_time {}",
                unacked.time <= lost_send_time
            );
            if unacked.time <= lost_send_time ||
                (pkts_num_with_seq.contains_key(&largest_acked) &&
                    pkts_num_with_seq.contains_key(&unacked.pkt_num) &&
                    *(pkts_num_with_seq.get(&largest_acked).unwrap()) >=
                        (*(pkts_num_with_seq
                            .get(&unacked.pkt_num)
                            .unwrap()) +
                            PACKET_THRESHOLD))
            {
                if unacked.in_flight {
                    trace!(
                        "{} packet {} lost on epoch {}",
                        trace_id,
                        unacked.pkt_num,
                        epoch
                    );
                }

                // We can't remove the lost packet from |self.sent| here, so
                // simply keep track of the number so it can be removed later.
                lost_pkt.push(unacked.pkt_num);
            } else {
                info!("loss time update");
                let loss_time = match self.loss_time[epoch] {
                    None => unacked.time + loss_delay,

                    Some(loss_time) =>
                        cmp::min(loss_time, unacked.time + loss_delay),
                };

                self.loss_time[epoch] = Some(loss_time);
                info!("epoch {} loss time {:?}", epoch, loss_time);
            }
        }

        if !lost_pkt.is_empty() {
            self.on_packets_lost(lost_pkt, epoch, now, trace_id);
        }
    }

    fn on_packet_acked(
        &mut self, pkt_num: u64, epoch: packet::Epoch, trace_id: &str,
    ) -> bool {
        // Check if packet is newly acked.
        if let Some(mut p) = self.sent[epoch].remove(&pkt_num) {
            self.acked[epoch].append(&mut p.frames);

            if p.in_flight {
                // OnPacketAckedCC(acked_packet)
                trace!("OnPacketAckedCC(acked_packet)");
                self.cc.on_packet_acked_cc(
                    &p,
                    self.rtt(),
                    self.min_rtt,
                    self.app_limited,
                    trace_id,
                );
            }

            return true;
        }

        // Is not newly acked.
        false
    }

    // TODO: move to Congestion Control and implement draft 24
    fn in_persistent_congestion(&mut self, _largest_lost_pkt: &Sent) -> bool {
        let _congestion_period = self.pto() * PERSISTENT_CONGESTION_THRESHOLD;

        // TODO: properly detect persistent congestion
        false
    }

    // TODO: move to Congestion Control
    fn on_packets_lost(
        &mut self, lost_pkt: Vec<u64>, epoch: packet::Epoch, now: Instant,
        trace_id: &str,
    ) {
        // Differently from OnPacketsLost(), we need to handle both
        // in-flight and non-in-flight packets, so need to keep track
        // of whether we saw any lost in-flight packet to trigger the
        // congestion event later.
        let mut largest_lost_pkt: Option<Sent> = None;

        for lost in lost_pkt {
            let mut p = self.sent[epoch].remove(&lost).unwrap();

            self.lost_count += 1;

            if !p.in_flight {
                continue;
            }

            self.cc.decrease_bytes_in_flight(p.size);

            self.lost[epoch].append(&mut p.frames);

            largest_lost_pkt = Some(p);
        }

        if let Some(largest_lost_pkt) = largest_lost_pkt {
            // CongestionEvent
            self.cc
                .congestion_event(largest_lost_pkt.time, now, trace_id);

            if self.in_persistent_congestion(&largest_lost_pkt) {
                self.cc.collapse_cwnd();
            }
        }
    }
}

impl std::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.loss_detection_timer {
            Some(v) => {
                let now = Instant::now();

                if v > now {
                    let d = v.duration_since(now);
                    write!(f, "timer={:?} ", d)?;
                } else {
                    write!(f, "timer=exp ")?;
                }
            },

            None => {
                write!(f, "timer=none ")?;
            },
        };

        write!(f, "latest_rtt={:?} ", self.latest_rtt)?;
        write!(f, "srtt={:?} ", self.smoothed_rtt)?;
        write!(f, "min_rtt={:?} ", self.min_rtt)?;
        write!(f, "rttvar={:?} ", self.rttvar)?;
        write!(f, "loss_time={:?} ", self.loss_time)?;
        write!(f, "loss_probes={:?} ", self.loss_probes)?;
        write!(f, "{:?} ", self.cc)?;

        Ok(())
    }
}

fn sub_abs(lhs: Duration, rhs: Duration) -> Duration {
    if lhs > rhs {
        lhs - rhs
    } else {
        rhs - lhs
    }
}
