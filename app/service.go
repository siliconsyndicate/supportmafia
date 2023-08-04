package app

// InitService this initializes all the busines logic services
func InitService(a *App) {

	a.Utils = InitUtils(&UtilsOpts{
		App: a,
	})

	a.User = InitUser(&UserOpts{
		App:    a,
		DB:     a.MongoDB.Client.Database(a.Config.UserConfig.DBName),
		ES:     a.ES.Conn(),
		Logger: a.Logger,
	})

	a.Auth = InitAuth(&AuthOpts{
		App:    a,
		DB:     a.MongoDB.Client.Database(a.Config.UserConfig.DBName),
		Logger: a.Logger,
	})

}
