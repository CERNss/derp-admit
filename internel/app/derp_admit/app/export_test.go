package app

// WithPruneScheduleForTest lets tests in package app_test shorten the audit
// pruner's schedule. It exists only in test builds.
var WithPruneScheduleForTest = withPruneSchedule
