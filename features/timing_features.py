# features/timing_features.py
"""
Specialized timing analysis for C2 beacon detection.
Implements autocorrelation, FFT-based periodicity, and jitter modeling.
"""

import numpy as np
from typing import Dict, List, Optional, Tuple
from scipy import stats, signal


class BeaconTimingAnalyzer:
    """
    Analyzes inter-arrival times to detect periodic beacons.
    
    Approach: Real C2 beacons are designed to look like random traffic
    by adding jitter (typically ±10-30%). But the underlying period
    is still detectable via autocorrelation, even at 30% jitter.
    
    Key: jittered beacons produce a SHARP PEAK in the autocorrelation
    function at the beacon interval. Normal web traffic has no such peak.
    """

    # Known C2 framework default intervals (seconds)
    KNOWN_INTERVALS = {
        60: "Cobalt Strike default (60s)",
        300: "Cobalt Strike common (5min)",
        3600: "Cobalt Strike stealth (1hr)",
        30: "Sliver aggressive",
        120: "Brute Ratel default",
        10: "Metasploit Meterpreter",
    }

    def analyze(self, timestamps_s: List[float]) -> Dict:
        """
        Full timing analysis from a list of packet timestamps.
        timestamps_s: Unix timestamps in seconds.
        """
        if len(timestamps_s) < 5:
            return self._empty()

        # Compute IATs
        ts = np.sort(np.array(timestamps_s))
        iats = np.diff(ts) * 1000  # Convert to ms

        features = {
            "iat_count": len(iats),
            "iat_mean_ms": float(np.mean(iats)),
            "iat_std_ms": float(np.std(iats)),
            "iat_cv": float(np.std(iats) / (np.mean(iats) + 1e-9)),
            "iat_min_ms": float(np.min(iats)),
            "iat_max_ms": float(np.max(iats)),
            "iat_median_ms": float(np.median(iats)),
        }

        # Skewness and kurtosis
        if len(iats) >= 4:
            features["iat_skewness"] = float(stats.skew(iats))
            features["iat_kurtosis"] = float(stats.kurtosis(iats))

        # Periodicity
        if len(iats) >= 8:
            score, period, confidence = self._autocorr_periodicity(iats)
            features["periodicity_score"] = score
            features["dominant_period_ms"] = period
            features["periodicity_confidence"] = confidence

            # FFT-based period estimate (double-check)
            fft_period = self._fft_period(iats)
            features["fft_period_ms"] = fft_period

            # Match against known intervals
            period_s = period / 1000
            features["matches_known_c2_interval"] = 0.0
            for known_s, name in self.KNOWN_INTERVALS.items():
                if abs(period_s - known_s) / known_s < 0.35:  # within 35% jitter
                    features["matches_known_c2_interval"] = 1.0
                    features["matched_c2_tool"] = name
                    break

        # Burst detection (exfil pattern: many fast packets then silence)
        features["burst_ratio"] = self._burst_ratio(iats)
        features["silence_ratio"] = self._silence_ratio(iats)

        # Regularity score: lower CV = more regular = more beacon-like
        # Invert so high score = high threat
        cv = features.get("iat_cv", 1.0)
        features["regularity_score"] = float(max(0.0, 1.0 - min(1.0, cv)))

        return features

    def _autocorr_periodicity(self,
                               iats: np.ndarray) -> Tuple[float, float, float]:
        """
        Autocorrelation-based periodicity detection.
        Returns (peak_score, period_ms, confidence).
        """
        # Normalize IATs
        normed = (iats - np.mean(iats)) / (np.std(iats) + 1e-9)

        # Full autocorrelation
        full_acf = np.correlate(normed, normed, mode='full')
        acf = full_acf[len(full_acf)//2:]  # Positive lags
        acf = acf / (acf[0] + 1e-9)

        if len(acf) < 3:
            return 0.0, 0.0, 0.0

        # Find peaks (skip lag 0)
        peaks, props = signal.find_peaks(
            acf[1:],
            height=0.2,
            prominence=0.15,
        )

        if len(peaks) == 0:
            return 0.0, 0.0, 0.0

        # Best peak
        best_peak_lag = peaks[np.argmax(acf[peaks + 1])] + 1
        peak_score = float(acf[best_peak_lag])
        period_ms = float(np.mean(iats) * best_peak_lag)

        # Confidence: how many IATs are close to the period?
        tolerance = 0.35  # 35% jitter tolerance
        n_close = sum(
            abs(iat - period_ms) / (period_ms + 1e-9) < tolerance
            for iat in iats
        )
        confidence = n_close / len(iats)

        return max(0.0, peak_score), period_ms, confidence

    def _fft_period(self, iats: np.ndarray) -> float:
        """
        FFT-based dominant period estimation.
        Useful for detecting jittered beacons where autocorrelation may miss.
        """
        if len(iats) < 16:
            return 0.0

        # Interpolate to uniform time grid
        t = np.cumsum(iats)
        t_uniform = np.linspace(t[0], t[-1], 256)
        signal_uniform = np.interp(t_uniform, t, iats)

        # FFT
        fft_vals = np.abs(np.fft.rfft(signal_uniform - np.mean(signal_uniform)))
        freqs = np.fft.rfftfreq(256, d=(t[-1] - t[0]) / 256)

        if len(freqs) < 2:
            return 0.0

        # Dominant frequency (skip DC)
        dominant_idx = np.argmax(fft_vals[1:]) + 1
        dominant_freq = freqs[dominant_idx]

        if dominant_freq <= 0:
            return 0.0

        return float(1.0 / dominant_freq)  # Period in ms

    def _burst_ratio(self, iats: np.ndarray) -> float:
        """
        Fraction of IATs that are very short (< 10ms).
        High = burst traffic (potential exfil or scan).
        """
        return float(np.mean(iats < 10))

    def _silence_ratio(self, iats: np.ndarray) -> float:
        """
        Fraction of IATs that are very long (> 10s).
        Alternating burst/silence = exfil pattern.
        """
        return float(np.mean(iats > 10000))

    def _empty(self) -> Dict:
        return {
            "iat_count": 0, "iat_mean_ms": 0.0, "iat_std_ms": 0.0,
            "iat_cv": 0.0, "iat_min_ms": 0.0, "iat_max_ms": 0.0,
            "iat_median_ms": 0.0, "periodicity_score": 0.0,
            "dominant_period_ms": 0.0, "periodicity_confidence": 0.0,
            "regularity_score": 0.0, "burst_ratio": 0.0, "silence_ratio": 0.0,
        }
