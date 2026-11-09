package main
import "os/exec"
func run(input string) { c:=exec.Command("sh","-c","tool --name "+input); _=c.Run() }
