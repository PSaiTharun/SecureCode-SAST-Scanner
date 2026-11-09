package main
import "os/exec"
func run(input string) { if input!="status" && input!="version" { return }; c:=exec.Command("tool","--name",input); _=c.Run() }
