package app

import (
	"supportmafia/server/handler"

	"github.com/getsentry/sentry-go"
	errors "github.com/vasupal1996/goerror"
)

type Utils interface {
	HandlePanic(*handler.RequestContext)
}

// UtilsOpts contains arguments to be accepted for new instance of Utility service
type UtilsOpts struct {
	App *App
}

// UtilsImpl implements Utility service
type UtilsImpl struct {
	App *App
}

// InitUtils returns initializes Utility service
func InitUtils(opts *UtilsOpts) Utils {
	i := &UtilsImpl{
		App: opts.App,
	}
	return i
}

// Global function for handling any panics
func (u *UtilsImpl) HandlePanic(requestCTX *handler.RequestContext) {
	panic := recover()
	if panic != nil {
		sentry.CurrentHub().Recover(panic)
		if requestCTX != nil {
			err := errors.New("Panic: unhandled exception occured", &errors.SomethingWentWrong)
			requestCTX.SetErr(err, 500)
		}
	}
}
