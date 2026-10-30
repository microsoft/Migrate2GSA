# Web Filtering OMv2: game plan

- **Decided:** preserve OMv1 and the CSV review workflow; add explicit OMv2
  conversion, provisioning, and export.
- **Reruns:** create missing objects, reuse equivalent configuration, and stop on
  conflicts. No automatic overwrite, deletion, or OMv1 unlinking.
- **Implemented locally:** per-profile web policies, ordered rules, explicit
  defaults including ContinueEvaluation, and reviewable export/retry CSVs.
- **Checked:** local contract/regression tests and documentation build.
- **Next:** authorized end-to-end validation with the available test tenant/reviewer.
- **Still to verify:** target-environment availability, URL matching, and
  multi-profile enforcement. Implementation is not yet tenant-validated.
