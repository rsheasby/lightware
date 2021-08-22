package lightware

import "github.com/rsheasby/lightwork"

func Recover(next lightwork.Handler) lightwork.Handler {
	return func(c *lightwork.Context) error {
		defer func() {
			p := recover()
			if p != nil {
				c.Log.WTFf("%v", p)
			}
		}()
		return next(c)
	}
}
