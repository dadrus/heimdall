package task

type Task interface {
	Schedule() bool
	Unschedule(reason error)
	BeginRun() bool
	Run()
	FinishRun() bool
}
