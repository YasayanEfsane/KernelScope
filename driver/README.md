# KernelScopeDriver

`KernelScopeDriver` is a non-PnP KMDF control driver. It uses only documented
process and image notification APIs and a fixed-capacity, nonpaged ring buffer.
It does not hook, patch, hide, scan files, inspect arbitrary memory, or perform
cryptographic work in kernel mode.

The named device uses `SDDL_DEVOBJ_SYS_ALL_ADM_ALL`; the I/O manager therefore
allows only LocalSystem and built-in Administrators to open it. Query, event,
and statistics IOCTLs require `FILE_READ_DATA`. Statistics reset additionally
requires a handle opened with `GENERIC_WRITE`, because its IOCTL requires
`FILE_WRITE_DATA`.

Notification callbacks execute at `PASSIVE_LEVEL` under the documented callback
contracts. They build one fixed 600-byte record on the stack and acquire a WDF
spin lock only while inserting it. The lock raises IRQL to `DISPATCH_LEVEL`.
No notification callback allocates memory. Retrieval copies at most 64 records
while holding the same lock, making the critical section strictly bounded.

See [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) for lifecycle, IRQL,
and failure-mode details.

