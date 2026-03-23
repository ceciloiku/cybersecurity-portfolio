---

## Detection 3 — Failed Login Followed by Success

### Logic
Correlates multiple failed login attempts followed by a successful authentication within a short time window.

### Why it matters
Indicates possible brute-force attack success or credential compromise.

### Limitations
- Requires proper event correlation
- May miss events across longer time windows

---

## Detection 4 — New User Account Created

### Logic
Detects creation of new user accounts.

### Why it matters
New accounts may indicate persistence or unauthorized access.

### Limitations
- May include legitimate administrative actions