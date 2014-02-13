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
			log.Println(err.Error())
			c.Flash.Error("Couldn't connect to the server.")
			return c.Render()
		}
		c.RenderArgs["serverResults"] = certInfo
	}
	return c.Render()
}
