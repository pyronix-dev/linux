# Linux drivers/ security audit — findings

Scope: `drivers/`, static source audit, report-only (no code changes).
Tree: `pyronix-dev/linux` at `ee9c669f9b` (7.3-rc5 era).
Method: pattern sweeps (user/firmware-controlled length used in `memcpy`/alloc,
allocation-size multiplication, `len - N` sizing) followed by manual
verification of each candidate against its data-flow and the framework
guarantees upstream of it.

I only report what I verified by reading the code. Candidates that turned out
safe are listed too, with *why*, so they don't get re-audited.

---

## Finding 1 — nvec_power: unbounded EC response length → OOB write (hardening)

**File:** `drivers/staging/nvec/nvec_power.c:196-205`
**Class:** Out-of-bounds write (CWE-787) + unsigned/int underflow (CWE-191)
**Severity:** Low — trust boundary is the embedded controller (see caveat).
Real bug worth a hardening fix.

```c
struct bat_response {
        u8 event_type;
        u8 length;          /* attacker/firmware-controlled, 0..255 */
        u8 sub_type;
        u8 status;
        union { char plc[30]; u16 plu; s16 pls; };
};
...
case MANUFACTURER:
        memcpy(power->bat_manu, &res->plc, res->length - 2);   /* dest is char[30] */
        power->bat_manu[res->length - 2] = '\0';
        break;
case MODEL:  /* same into bat_model[30] */
case TYPE:   /* same into bat_type[30]  */
```

`res` is the raw NVEC response buffer (`nvec_power_notifier` / `nvec_power_bat_notifier`,
`res = data`). `res->length` is used directly to size the copy into three fixed
30-byte fields, with **no upper bound and no lower bound**:

1. **Overflow:** `res->length` can be up to 255. `res->length - 2` (up to 253)
   is memcpy'd into `power->bat_manu[30]`, overrunning the `nvec_power` struct by
   up to ~223 bytes. The following `power->bat_manu[res->length - 2] = '\0'`
   writes a byte up to index 253 — also out of bounds.
2. **Underflow:** `res->length` is a `u8`; `res->length - 2` is evaluated as `int`,
   so `length == 0` or `1` gives `-2`/`-1`, which converts to a huge `size_t` for
   `memcpy` → catastrophic copy.
3. **OOB read:** the source `&res->plc` is only 30 bytes; a large `length` also
   reads past it.

**Caveat on severity:** the data originates from the Tegra NVEC embedded
controller, normally treated as trusted hardware, so this is not an
unprivileged local/remote escalation. It is a robustness/hardening gap: a
malfunctioning or compromised EC turns a battery-info notification into kernel
memory corruption. Note `nvec_power` also runs `strncmp(power->bat_type, "Li", 30)`
right after, assuming a bounded, terminated buffer.

**Suggested fix (illustrative — not applied, this is report-only):**
```c
size_t n;
if (res->length < 2)
        break;                      /* or dev_warn + return */
n = min_t(size_t, res->length - 2, sizeof(power->bat_manu) - 1);
memcpy(power->bat_manu, &res->plc, n);
power->bat_manu[n] = '\0';
```
Apply the same clamp to MODEL and TYPE.

---

## Verified safe (candidates that looked dangerous but are not)

These matched the same risky patterns; each is bounded by a check I confirmed.
Listed so the next audit can skip them.

- **`drivers/staging/rtl8723bs/os_dep/ioctl_cfg80211.c:881` — `cfg80211_rtw_add_key`
  seq copy.** `memcpy(param->u.crypt.seq, params->seq, params->seq_len)` where
  `seq` is `u8[8]` and `seq_len` can be up to 16 (nl80211 policy
  `NL80211_ATTR_KEY_SEQ`/`NL80211_KEY_SEQ` both `.len = 16`). *Looks* like an
  8-byte overflow, but `struct ieee_param`'s union is sized by its largest
  member `add_sta` (~52 bytes, incl. `struct ieee80211_ht_cap`), not by `crypt`
  (~36 bytes). The up-to-8-byte overrun stays inside the union slack of the
  `kzalloc(sizeof(*param) + key_len)` allocation, and the clobbered `key_len`/
  `key[]` bytes are overwritten immediately afterward. No heap overflow.
  (Still ugly — a defensive `min(seq_len, sizeof seq)` would be reasonable — but
  not a memory-safety bug as written.)

- **`drivers/staging/greybus/raw.c:127` — `gb_raw_send`.**
  `kmalloc(len + sizeof(*request))` then `copy_from_user(&request->data[0], data, len)`.
  No integer overflow: the only caller `raw_write()` rejects `count > MAX_PACKET_SIZE`
  before calling, and `data[]` is `__counted_by(len)`.

- **`drivers/media/cec/usb/extron-da-hd-4k-plus/cec-splitter.c:159` —
  `cec_out_passthrough`.** `memcpy(msg.msg + 1, in_msg->msg + 1, msg.len - 1)`
  would underflow if `in_msg->len == 0`, but the CEC core drops zero-length
  received messages before delivery (`cec-adap.c:1153`,
  `WARN_ON(!msg->len || msg->len > CEC_MAX_MSG_SIZE)`), so `len >= 1` here.
  Max copy is 15 bytes into a 16-byte buffer. Safe.

---

## Limitations / honest notes

- This is a static pass over a subset of `drivers/` driven by a few bug-class
  patterns; it is **not** exhaustive. Mainline's low-hanging fruit is already
  swept by syzkaller/Coccinelle/smatch, so the highest-value follow-up is
  dynamic fuzzing of a chosen driver's ioctl/read/write/netlink surface, not
  more grepping.
- I focused on `staging/` and device-response paths where review is thinner.
  Larger locally-reachable attack surfaces (`drivers/media` v4l2 ioctls,
  `drivers/gpu/drm` ioctls, USB descriptor parsing under `drivers/usb`) were not
  covered here and are the natural next targets.
- Nothing here should be treated as a confirmed exploitable vulnerability
  without a PoC. Finding 1 is a real out-of-bounds write; its security impact is
  gated by the EC trust boundary.

## Suggested next steps
1. If you want Finding 1 fixed: I can prepare the clamp patch for
   `nvec_power.c` on your branch (you chose report-only, so I stopped short).
2. Pick one locally-reachable subsystem (media v4l2, drm, or usb) and I'll do a
   deeper, targeted pass there.
3. For real assurance, stand up syzkaller against the target driver — static
   review alone won't find the interesting state-dependent bugs.
