import time
import hashlib
import sys
import os
import matplotlib.pyplot as plt
import numpy as np
import hmac
from collections import defaultdict
from ascon import encrypt as ascon_encrypt, decrypt as ascon_decrypt

# ==============================================================================
# 1. & 2. 核心加密引擎和主类 
# ==============================================================================
class ChronoCryptSPN:
    BLOCK_SIZE = 16; ROUNDS = 8
    S_BOX_BASE = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
    S_BOXES = [ S_BOX_BASE, [val ^ 0x1 for val in S_BOX_BASE], [val ^ 0x2 for val in S_BOX_BASE], [val ^ 0x3 for val in S_BOX_BASE] ]
    INV_S_BOXES = [ [s.index(i) for i in range(16)] for s in S_BOXES ]
    ROUND_CONSTANTS = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
    def __init__(self, session_key: bytes, theta: bytes):
        if len(session_key) != 16 or len(theta) != 16: raise ValueError("Key/Theta must be 16 bytes.")
        self.theta = theta; self.round_keys = self._key_schedule(session_key)
        self.sbox_selectors = [b % len(self.S_BOXES) for b in self.theta[:self.ROUNDS]]
        self.permutation_selectors = [(self.theta[i], self.theta[i+1]) for i in range(0, self.ROUNDS, 2)]
    def _key_schedule(self, key: bytes) -> list[bytes]:
        round_keys, current_key = [key], list(key)
        for i in range(self.ROUNDS):
            current_key = current_key[1:] + current_key[:1]; current_key[0] ^= self.ROUND_CONSTANTS[i]
            round_keys.append(bytes(current_key))
        return round_keys
    def _add_round_key(self, s, rk):
        for i in range(self.BLOCK_SIZE): s[i] ^= rk[i]
    def _substitution(self, s, rn, inv=False):
        sbox = self.INV_S_BOXES[self.sbox_selectors[rn]] if inv else self.S_BOXES[self.sbox_selectors[rn]]
        for i in range(self.BLOCK_SIZE): s[i] = (sbox[(s[i] >> 4) & 0x0F] << 4) | sbox[s[i] & 0x0F]
    def _permutation(self, s, rn, inv=False):
        selectors = reversed(self.permutation_selectors) if inv else self.permutation_selectors
        for s1, s2 in selectors:
            i1, i2 = s1 % self.BLOCK_SIZE, s2 % self.BLOCK_SIZE
            if i1 != i2: s[i1], s[i2] = s[i2], s[i1]
    def encrypt_block(self, b):
        s = bytearray(b); self._add_round_key(s, self.round_keys[0])
        for i in range(self.ROUNDS - 1): self._substitution(s, i); self._permutation(s, i); self._add_round_key(s, self.round_keys[i + 1])
        self._substitution(s, self.ROUNDS - 1); self._add_round_key(s, self.round_keys[self.ROUNDS]); return bytes(s)
    def decrypt_block(self, b):
        s = bytearray(b); self._add_round_key(s, self.round_keys[self.ROUNDS]); self._substitution(s, self.ROUNDS - 1, inv=True)
        for i in range(self.ROUNDS - 2, -1, -1): self._add_round_key(s, self.round_keys[i+1]); self._permutation(s, i, inv=True); self._substitution(s, i, inv=True)
        self._add_round_key(s, self.round_keys[0]); return bytes(s)

class ChronoCryptAEAD:
    TAG_SIZE=16
    @staticmethod
    def _pad(d, bs): return d + bytes([bs - len(d) % bs] * (bs - len(d) % bs))
    @staticmethod
    def _unpad(d): return d[:-d[-1]]
    @staticmethod
    def serialize_state(sv): return ";".join([f"{k}:{v}" for k,v in sorted(sv.items())]).encode('utf-8')
    @staticmethod
    def generate_params(mk, did, ts, sv):
        ss = ChronoCryptAEAD.serialize_state(sv)
        kd = hashlib.sha256(b'enc'+mk+str(ts).encode()+ss+did.encode()).digest()[:16]
        kmac = hashlib.sha256(b'mac'+mk+str(ts).encode()+ss+did.encode()).digest()[:16]
        theta = hashlib.sha256(b'cfg'+mk+str(ts).encode()+ss+did.encode()).digest()[:16]
        return kd, kmac, theta
    @staticmethod
    def encrypt(mk, did, pt, sv, ad=b''):
        ts = int(time.time_ns()); kd, kmac, theta = ChronoCryptAEAD.generate_params(mk, did, ts, sv)
        cipher = ChronoCryptSPN(kd, theta); pt_padded = ChronoCryptAEAD._pad(pt, 16)
        iv = os.urandom(16); ct_core = bytearray(); prev = iv
        for i in range(0, len(pt_padded), 16):
            blk = pt_padded[i:i+16]; to_enc = bytes([b^p for b,p in zip(blk, prev)])
            enc_blk = cipher.encrypt_block(to_enc); ct_core.extend(enc_blk); prev = enc_blk
        mac = hmac.new(kmac, ad+iv+ct_core, hashlib.sha256).digest()[:16]
        return iv + ct_core + mac, ts
    @staticmethod
    def decrypt(mk, did, ct, ts, psv, ad=b''):
        kd, kmac, theta = ChronoCryptAEAD.generate_params(mk, did, ts, psv)
        iv=ct[:16]; tag=ct[-16:]; ct_core=ct[16:-16]
        if not hmac.compare_digest(hmac.new(kmac, ad+iv+ct_core, hashlib.sha256).digest()[:16], tag): raise ValueError("Auth failed")
        cipher = ChronoCryptSPN(kd, theta); pt_padded = bytearray(); prev = iv
        for i in range(0, len(ct_core), 16):
            blk = ct_core[i:i+16]; dec_blk = cipher.decrypt_block(blk)
            pt_blk = bytes([d^p for d,p in zip(dec_blk, prev)]); pt_padded.extend(pt_blk); prev = blk
        return ChronoCryptAEAD._unpad(bytes(pt_padded))

# ==============================================================================
# 3. 实验评估函数
# ==============================================================================
def benchmark_operation(func, *args, **kwargs):
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    return result, (time.perf_counter() - start_time) * 1000

def run_full_evaluation(n_runs=20):
    results = defaultdict(list)
    master_key = os.urandom(16); device_id = "Sensor-Pump-101"
    plaintext = (b'This is a sample sensor reading payload!! ' * 3)
    ad = b'metadata'; nonce = os.urandom(16)
    real_state = {'temp': 75.2, 'pressure': 14.7, 'rpm': 2400}
    print("="*60 + f"\nRunning Performance Evaluation ({n_runs} iterations)\n" + "="*60)
    for i in range(n_runs):
        print(f"\rRunning iteration {i+1}/{n_runs}...", end="")
        (ct, ts), l_cc_e = benchmark_operation(ChronoCryptAEAD.encrypt, master_key, device_id, plaintext, real_state, ad=ad)
        _, l_cc_d = benchmark_operation(ChronoCryptAEAD.decrypt, master_key, device_id, ct, ts, real_state, ad=ad)
        (_, l_ser), (_, l_gen) = benchmark_operation(ChronoCryptAEAD.serialize_state, real_state), benchmark_operation(ChronoCryptAEAD.generate_params, master_key, device_id, int(time.time_ns()), real_state)
        ascon_key = os.urandom(16)
        ascon_ct, l_asc_e = benchmark_operation(ascon_encrypt, key=ascon_key, nonce=nonce, associateddata=ad, plaintext=plaintext, variant="Ascon-128")
        _, l_asc_d = benchmark_operation(ascon_decrypt, key=ascon_key, nonce=nonce, associateddata=ad, ciphertext=ascon_ct, variant="Ascon-128")
        for k, v in {'cc_encrypt':l_cc_e, 'cc_decrypt':l_cc_d, 'ascon_encrypt':l_asc_e, 'ascon_decrypt':l_asc_d, 'stateful_overhead':l_ser+l_gen}.items(): results[k].append(v)
    print("\n\nEvaluation complete.\n")
    stats = {key: (np.mean(val), np.std(val)) for key, val in results.items()}
    mem_master = sys.getsizeof(master_key)
    kd, kmac, theta = ChronoCryptAEAD.generate_params(master_key, device_id, int(time.time_ns()), real_state)
    mem_dynamic = sys.getsizeof(kd) + sys.getsizeof(kmac) + sys.getsizeof(theta)
    mem_state = sys.getsizeof(ChronoCryptAEAD.serialize_state(real_state))
    return {'stats': stats, 'memory': {'master': mem_master, 'dynamic': mem_dynamic, 'state': mem_state}}

def run_sensitivity_analysis(n_runs=20):
    print("="*60 + f"\nRunning Sensitivity Analysis ({n_runs} iterations)\n" + "="*60)
    results = defaultdict(list); total_bits = 16 * 8
    for i in range(n_runs):
        print(f"\rRunning iteration {i+1}/{n_runs}...", end="")
        master_key = os.urandom(16); device_id = "Sensor-Pump-101"
        base_state = {'temp': 75.2}; changed_state = {'temp': 75.3}
        base_ts = int(time.time_ns()); changed_ts = base_ts + 1
        kd_b, km_b, _ = ChronoCryptAEAD.generate_params(master_key, device_id, base_ts, base_state)
        kd_s, km_s, _ = ChronoCryptAEAD.generate_params(master_key, device_id, base_ts, changed_state)
        kd_t, km_t, _ = ChronoCryptAEAD.generate_params(master_key, device_id, changed_ts, base_state)
        results['kd_state'].append(sum(bin(x^y).count('1') for x,y in zip(kd_b, kd_s))/total_bits)
        results['kmac_state'].append(sum(bin(x^y).count('1') for x,y in zip(km_b, km_s))/total_bits)
        results['kd_time'].append(sum(bin(x^y).count('1') for x,y in zip(kd_b, kd_t))/total_bits)
        results['kmac_time'].append(sum(bin(x^y).count('1') for x,y in zip(km_b, km_t))/total_bits)
    print("\n\nAnalysis complete.\n")
    stats = {key: (np.mean(val), np.std(val)) for key, val in results.items()}
    return stats

# ==============================================================================
# 4. 负载大小分析 
# ==============================================================================
def run_payload_size_analysis(payload_sizes, n_runs=10):
    print("="*60 + f"\nRunning Payload Size vs. Throughput Analysis\n" + "="*60)
    # 存储每次运行的原始延迟
    raw_latencies = defaultdict(lambda: defaultdict(list))
    master_key = os.urandom(16); device_id = "Sensor-Pump-101"; ad = b'metadata'
    real_state = {'temp': 75.2, 'pressure': 14.7, 'rpm': 2400}

    for size in payload_sizes:
        print(f"Testing payload size: {size} bytes")
        plaintext = os.urandom(size)
        for i in range(n_runs):
            print(f"\r  - Iteration {i+1}/{n_runs}...", end="")
            _, l_cc_e = benchmark_operation(ChronoCryptAEAD.encrypt, master_key, device_id, plaintext, real_state, ad=ad)
            ascon_key = os.urandom(16); nonce = os.urandom(16)
            _, l_asc_e = benchmark_operation(ascon_encrypt, key=ascon_key, nonce=nonce, associateddata=ad, plaintext=plaintext, variant="Ascon-128")
            raw_latencies['chrono'][size].append(l_cc_e)
            raw_latencies['ascon'][size].append(l_asc_e)
        print()

    # 计算每个size的吞吐量均值和标准差
    throughput_stats = defaultdict(dict)
    for algo in ['chrono', 'ascon']:
        for size in payload_sizes:
            latencies_ms = raw_latencies[algo][size]
            # 为每一次运行计算吞吐量
            throughputs_kb_s = [(size / 1024) / (lat / 1000) for lat in latencies_ms if lat > 0]
            if throughputs_kb_s:
                mean_tp = np.mean(throughputs_kb_s)
                std_tp = np.std(throughputs_kb_s)
                throughput_stats[algo][size] = (mean_tp, std_tp)
            else:
                throughput_stats[algo][size] = (0, 0)
            
    print("\nAnalysis complete.\n")
    return throughput_stats

# ==============================================================================
# 5. 统一的可视化函数 (升级: 吞吐量图表增加置信区间)
# ==============================================================================
def create_all_visualizations(perf_metrics, sens_metrics, payload_stats, payload_sizes):
    plt.style.use('seaborn-v0_8-whitegrid')
    stats = perf_metrics['stats']

    # --- Plot 1, 2, 3 (无变化) ---
    labels, x, width = ['Encryption', 'Decryption'], np.arange(2), 0.35
    ascon_m, ascon_s = [stats['ascon_encrypt'][0], stats['ascon_decrypt'][0]], [stats['ascon_encrypt'][1], stats['ascon_decrypt'][1]]
    chrono_m, chrono_s = [stats['cc_encrypt'][0], stats['cc_decrypt'][0]], [stats['cc_encrypt'][1], stats['cc_decrypt'][1]]
    fig, ax = plt.subplots(figsize=(8, 5))
    r1=ax.bar(x-width/2, ascon_m, width, yerr=ascon_s, label='Ascon-128', color='skyblue', capsize=5); r2=ax.bar(x+width/2, chrono_m, width, yerr=chrono_s, label='ChronoCrypt (SPN+HMAC)', color='coral', capsize=5)
    ax.set_ylabel('Latency (ms)'); ax.set_title('AEAD Latency Comparison'); ax.set_xticks(x); ax.set_xticklabels(labels); ax.legend(); ax.bar_label(r1, fmt='%.3f'); ax.bar_label(r2, fmt='%.3f'); fig.tight_layout(); plt.savefig("1_latency_comparison.pdf"); plt.show()

    mean_oh, mean_cc_e = stats['stateful_overhead'][0], stats['cc_encrypt'][0]
    base_lat = max(0, mean_cc_e - mean_oh)
    overhead_percent = (mean_oh / mean_cc_e) * 100 if mean_cc_e > 0 else 0
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar('ChronoCrypt', base_lat, label='AEAD Core (avg)', color='lightgreen'); ax.bar('ChronoCrypt', mean_oh, bottom=base_lat, label='Stateful Overhead (avg)', color='salmon')
    ax.set_ylabel('Latency (ms)'); title=f"ChronoCrypt Encryption Latency Composition\n(Stateful Overhead is ~{overhead_percent:.2f}% of Core Latency)"; ax.set_title(title); ax.legend(loc='upper left')
    plt.text('ChronoCrypt', base_lat/2, f'{base_lat:.4f} ms', ha='center', va='center', c='k'); plt.text('ChronoCrypt', base_lat+mean_oh/2, f'{mean_oh:.4f} ms', ha='center', va='center', c='k'); fig.tight_layout(); plt.savefig("2_overhead_composition.pdf"); plt.show()
    
    mem_metrics = perf_metrics['memory']
    mem_labels=['Master Key', 'Dynamic Keys\n& Theta', 'State Vector']; mem_values=[mem_metrics['master'], mem_metrics['dynamic'], mem_metrics['state']]
    fig, ax = plt.subplots(figsize=(8, 5)); bars = ax.bar(mem_labels, mem_values, color=['#1f77b4', '#ff7f0e', '#2ca02c']); ax.set_ylabel('Size (Bytes)'); ax.set_title('RAM Memory Footprint'); ax.bar_label(bars); fig.tight_layout(); plt.savefig("3_memory_footprint.pdf"); plt.show()
    
    # --- Plot 4: 敏感性分析 (无变化) ---
    labels = ['Kd\n(State Δ)', 'Kmac\n(State Δ)', 'Kd\n(Time Δ)', 'Kmac\n(Time Δ)']
    means = [sens_metrics['kd_state'][0], sens_metrics['kmac_state'][0], sens_metrics['kd_time'][0], sens_metrics['kmac_time'][0]]
    stds = [sens_metrics['kd_state'][1], sens_metrics['kmac_state'][1], sens_metrics['kd_time'][1], sens_metrics['kmac_time'][1]]
    colors = ['#1f77b4', '#ff7f0e', '#aec7e8', '#ffbb78']
    fig, ax = plt.subplots(figsize=(10, 6)); bars = ax.bar(labels, means, yerr=stds, color=colors, capsize=5)
    ax.axhline(y=0.5, color='gray', linestyle='--', label='Ideal Avalanche (50%)'); ax.set_ylabel('Bit Difference Ratio'); ax.set_ylim(0, 0.7); ax.set_title('Key Sensitivity to Minor Input Changes'); ax.legend(); ax.bar_label(bars, fmt='{:.3f}')
    plt.subplots_adjust(bottom=0.15); fig.tight_layout(); plt.savefig("4_sensitivity_analysis.pdf"); plt.show()

    # --- Plot 5: 吞吐量分析 (升级: 增加置信区间) ---
    chrono_tp_means = np.array([payload_stats['chrono'][s][0] for s in payload_sizes])
    chrono_tp_stds = np.array([payload_stats['chrono'][s][1] for s in payload_sizes])
    ascon_tp_means = np.array([payload_stats['ascon'][s][0] for s in payload_sizes])
    ascon_tp_stds = np.array([payload_stats['ascon'][s][1] for s in payload_sizes])
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # 绘制ChronoCrypt的均值线和置信区间
    ax.plot(payload_sizes, chrono_tp_means, marker='o', linestyle='-', color='coral', label='ChronoCrypt (Mean)')
    ax.fill_between(payload_sizes, chrono_tp_means - chrono_tp_stds, chrono_tp_means + chrono_tp_stds, color='coral', alpha=0.2)
    
    # 绘制Ascon-128的均值线和置信区间
    ax.plot(payload_sizes, ascon_tp_means, marker='s', linestyle='--', color='skyblue', label='Ascon-128 (Mean)')
    ax.fill_between(payload_sizes, ascon_tp_means - ascon_tp_stds, ascon_tp_means + ascon_tp_stds, color='skyblue', alpha=0.2)
    
    ax.set_xlabel('Payload Size (Bytes)'); ax.set_ylabel('Encryption Throughput (KB/s)')
    ax.set_title('Throughput vs. Payload Size with Confidence Intervals (±1 std)'); ax.grid(True, which='both', linestyle='--')
    ax.set_xscale('log'); ax.legend(); fig.tight_layout(); plt.savefig("5_throughput_analysis_with_intervals.pdf"); plt.show()

if __name__ == '__main__':
    # 1. 运行性能评估
    perf_metrics = run_full_evaluation(n_runs=20)
    
    # 2. 运行敏感性分析
    sens_metrics = run_sensitivity_analysis(n_runs=20)
    
    # 3. 运行负载大小分析
    payload_sizes_to_test = [16, 32, 64, 128, 256, 512, 1024]
    payload_stats = run_payload_size_analysis(payload_sizes_to_test, n_runs=10)
    
    # 4. 运行功能性测试
    # ... (省略以保持简洁) ...
    
    # 5. 创建所有可视化
    if perf_metrics and sens_metrics and payload_stats:
        create_all_visualizations(perf_metrics, sens_metrics, payload_stats, payload_sizes_to_test)