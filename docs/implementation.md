# Implementation overview

The kernel supplies a capability for the object selected at runtime. Its
bounds and permissions set the maximum access to that object. The verifier
records what each supported instruction needs, and the JIT emits code that
applies those restrictions when the instruction runs.

1. **Verification.** In `kernel/bpf/verifier.c`, `record_object_use()`
   records the object association, offset range, width, and direction.
   Rewritten instructions must have matching records in the final bytecode.
2. **Object selection.** The entry path provides an invocation's stack
   capability. Providers in `kernel/bpf/arraymap.c`, `kernel/bpf/hashtab.c`,
   and `kernel/bpf/ringbuf.c` establish bounds for selected map values
   and payloads.
3. **Direct access.** In `arch/arm64/net/bpf_jit_comp.c`,
   `prepare_object_caps()` checks admission. `emit_object_cap_insn()` emits
   the derivation of a narrower capability and the load or store that uses
   it. Morello checks the entire access against the resulting capability.
4. **Gateway calls.** Dedicated entry points check arguments for supported
   operations that need trusted kernel code. Lookups and reservations can
   return a bounded capability. Release checks the reservation's identity.

The supported profile admits one function and either a stack-only workload
or one supported map. A program selected for protection must compile through
the protected JIT before it can run. The containment argument assumes correct
object selection, live backing storage, correct instruction and object
classification, and complete mediation of direct accesses and gateways.

The numbered patches can be read in order. Run `./scripts/run.sh --describe
TARGET` to see the precise selection for an example.
