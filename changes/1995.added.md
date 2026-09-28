Add read-only `audit.heads` and `audit.export` admin methods for anchoring the
audit log outside the runtime. `astrid audit heads` reports every chain's
retained count, total pruned entries and head hash, signed by the runtime key
over a fixed length-prefixed encoding (`astrid.audit.heads.v1`) with no
pre-hash. `astrid audit export` pages one chain's stored entries with their
exact signing bytes, content hashes and signatures, together with the chain's
latest prune receipt, and returns a cursor that also resumes after later
appends. The methods require the `audit:heads` and `audit:export`
capabilities. Successful calls are not written to the audit log, so polling
does not grow it; denied calls are still recorded.

Chain metadata now counts the entries each prune removes, in the same update
that lowers the retained count. Chains pruned at most once before this release
report an exact total. A chain pruned more than once before it reports the
total as unknown, signed as `u64::MAX`.
