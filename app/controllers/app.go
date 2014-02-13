package controllers

import (
	"github.com/gokyle/tlsplain/getcert"
	"github.com/robfig/revel"
)

type App struct {
	*revel.Controller
}

func (c App) Index(host string) revel.Result {
	c.RenderArgs["homeActive"] = true

	if host != "" {
		certInfo, err := getcert.Fetch(host)
		if err != nil {
			c.Flash.Error("Couldn't connect to the server.")
			return c.Render()
		}
		c.RenderArgs["serverResults"] = certInfo
		revel.INFO.Printf("%v", certInfo)
	}
	return c.Render()
}
