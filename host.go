package main

import (
"bufio"
"fmt"
"os"
"time"
	"sync"
	"golang.org/x/crypto/ssh"
)

const maxInputLength int = 1024

// Host is the bridge between sshd and chat modules
type Host struct {
	listener *SSHListener
	auth     *Auth
	mu    sync.Mutex
	count int
}

// NewHost creates a Host on top of an existing listener.
func NewHost(listener *SSHListener, auth *Auth) *Host {
	h := Host{
		listener: listener,
		auth:     auth,
	}
	return &h
}

/*
func (h *Host) isOp(conn Connection) bool {
	key := conn.PublicKey()
	if key == nil {
		return false
	}
	return h.auth.IsOp(key)
}

*/

type Identity struct {
        ssh.ServerConn
        id      string
        created time.Time
}


// Connect a specific Terminal to this host and its room.
func (h *Host) Connect(sconn *ssh.ServerConn, ch ssh.NewChannel) {
     id := Identity{*sconn, sconn.User(), time.Now()}
     defer sconn.Close()

	h.mu.Lock()
	h.count++
	h.mu.Unlock()

	channel, _, err := ch.Accept()
	if err != nil {
	   fmt.Fprintf(os.Stderr, "accept failed: %s\n", err)
		return
	}
/*
	user := message.NewUserScreen(id, term)
	cfg := user.Config()
	cfg.Theme = &h.theme
	user.SetConfig(cfg)
	go user.Consume()

	// Close term once user is closed.
	defer user.Close()
	defer term.Close()


	member, err := h.Join(user)
	if err != nil {
		// Try again...
		id.SetName(fmt.Sprintf("Guest%d", count))
		member, err = h.Join(user)
	}
	if err != nil {
		logger.Errorf("[%s] Failed to join: %s", term.Conn.RemoteAddr(), err)
		return
	}

	// Successfully joined.
	term.SetPrompt(GetPrompt(user))
	term.AutoCompleteCallback = h.AutoCompleteFunction(user)
	user.SetHighlight(user.Name())

	// Should the user be op'd on join?
	if h.isOp(term.Conn) {
		h.Room.Ops.Add(set.Itemize(member.ID(), member))
	}
	*/

	fmt.Fprintf(os.Stderr, "[%s] Joined: %s\n", sconn.RemoteAddr(), id.id)
        scanner := bufio.NewScanner(channel)
        for scanner.Scan() {
            fmt.Printf("{\"from\": \"%s\", \"what\": \"%s\"}\n", id.id, scanner.Text())
        }
        if err := scanner.Err(); err != nil {
            fmt.Fprintln(os.Stderr, "There was an error with the scanner in attached container", err)
        }
	defer channel.Close()
	fmt.Fprintf(os.Stderr, "[%s] Leaving: %s\n", sconn.RemoteAddr(), id.id)
}

// Serve our chat room onto the listener
func (h *Host) Serve() {
	h.listener.HandlerFunc = h.Connect
	h.listener.Serve()
}

/*
func (h *Host) completeName(partial string) string {
	names := h.NamesPrefix(partial)
	if len(names) == 0 {
		// Didn't find anything
		return ""
	}

	return names[len(names)-1]
}

func (h *Host) completeCommand(partial string) string {
	for cmd := range h.commands {
		if strings.HasPrefix(cmd, partial) {
			return cmd
		}
	}
	return ""
}

// AutoCompleteFunction returns a callback for terminal autocompletion
func (h *Host) AutoCompleteFunction(u *message.User) func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
	return func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
		if key != 9 {
			return
		}

		if line == "" || strings.HasSuffix(line[:pos], " ") {
			// Don't autocomplete spaces.
			return
		}

		fields := strings.Fields(line[:pos])
		isFirst := len(fields) < 2
		partial := ""
		if len(fields) > 0 {
			partial = fields[len(fields)-1]
		}
		posPartial := pos - len(partial)

		var completed string
		if isFirst && strings.HasPrefix(partial, "/") {
			// Command
			completed = h.completeCommand(partial)
			if completed == "/reply" {
				replyTo := u.ReplyTo()
				if replyTo != nil {
					name := replyTo.Name()
					_, found := h.GetUser(name)
					if found {
						completed = "/msg " + name
					} else {
						u.SetReplyTo(nil)
					}
				}
			}
		} else {
			// Name
			completed = h.completeName(partial)
			if completed == "" {
				return
			}
			if isFirst {
				completed += ":"
			}
		}
		completed += " "

		// Reposition the cursor
		newLine = strings.Replace(line[posPartial:], partial, completed, 1)
		newLine = line[:posPartial] + newLine
		newPos = pos + (len(completed) - len(partial))
		ok = true
		return
	}
}

// GetUser returns a message.User based on a name.
func (h *Host) GetUser(name string) (*message.User, bool) {
	m, ok := h.MemberByID(name)
	if !ok {
		return nil, false
	}
	return m.User, true
}

// InitCommands adds host-specific commands to a Commands container. These will
// override any existing commands.
func (h *Host) InitCommands(c *chat.Commands) {
	c.Add(chat.Command{
		Prefix:     "/msg",
		PrefixHelp: "USER MESSAGE",
		Help:       "Send MESSAGE to USER.",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			args := msg.Args()
			switch len(args) {
			case 0:
				return errors.New("must specify user")
			case 1:
				return errors.New("must specify message")
			}

			target, ok := h.GetUser(args[0])
			if !ok {
				return errors.New("user not found")
			}

			m := message.NewPrivateMsg(strings.Join(args[1:], " "), msg.From(), target)
			room.Send(&m)

			txt := fmt.Sprintf("[Sent PM to %s]", target.Name())
			ms := message.NewSystemMsg(txt, msg.From())
			room.Send(ms)
			target.SetReplyTo(msg.From())
			return nil
		},
	})

	c.Add(chat.Command{
		Prefix:     "/reply",
		PrefixHelp: "MESSAGE",
		Help:       "Reply with MESSAGE to the previous private message.",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			args := msg.Args()
			switch len(args) {
			case 0:
				return errors.New("must specify message")
			}

			target := msg.From().ReplyTo()
			if target == nil {
				return errors.New("no message to reply to")
			}

			name := target.Name()
			_, found := h.GetUser(name)
			if !found {
				return errors.New("user not found")
			}

			m := message.NewPrivateMsg(strings.Join(args, " "), msg.From(), target)
			room.Send(&m)

			txt := fmt.Sprintf("[Sent PM to %s]", name)
			ms := message.NewSystemMsg(txt, msg.From())
			room.Send(ms)
			return nil
		},
	})

	c.Add(chat.Command{
		Prefix:     "/whois",
		PrefixHelp: "USER",
		Help:       "Information about USER.",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			args := msg.Args()
			if len(args) == 0 {
				return errors.New("must specify user")
			}

			target, ok := h.GetUser(args[0])
			if !ok {
				return errors.New("user not found")
			}

			id := target.Identifier.(*Identity)
			var whois string
			switch room.IsOp(msg.From()) {
			case true:
				whois = id.WhoisAdmin()
			case false:
				whois = id.Whois()
			}
			room.Send(message.NewSystemMsg(whois, msg.From()))

			return nil
		},
	})

	// Hidden commands
	c.Add(chat.Command{
		Prefix: "/version",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			room.Send(message.NewSystemMsg(h.Version, msg.From()))
			return nil
		},
	})

	timeStarted := time.Now()
	c.Add(chat.Command{
		Prefix: "/uptime",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			room.Send(message.NewSystemMsg(humanSince(time.Since(timeStarted)), msg.From()))
			return nil
		},
	})

	// Op commands
	c.Add(chat.Command{
		Op:         true,
		Prefix:     "/kick",
		PrefixHelp: "USER",
		Help:       "Kick USER from the server.",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			if !room.IsOp(msg.From()) {
				return errors.New("must be op")
			}

			args := msg.Args()
			if len(args) == 0 {
				return errors.New("must specify user")
			}

			target, ok := h.GetUser(args[0])
			if !ok {
				return errors.New("user not found")
			}

			body := fmt.Sprintf("%s was kicked by %s.", target.Name(), msg.From().Name())
			room.Send(message.NewAnnounceMsg(body))
			target.Close()
			return nil
		},
	})

	c.Add(chat.Command{
		Op:         true,
		Prefix:     "/ban",
		PrefixHelp: "USER [DURATION]",
		Help:       "Ban USER from the server.",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			// TODO: Would be nice to specify what to ban. Key? Ip? etc.
			if !room.IsOp(msg.From()) {
				return errors.New("must be op")
			}

			args := msg.Args()
			if len(args) == 0 {
				return errors.New("must specify user")
			}

			target, ok := h.GetUser(args[0])
			if !ok {
				return errors.New("user not found")
			}

			var until time.Duration = 0
			if len(args) > 1 {
				until, _ = time.ParseDuration(args[1])
			}

			id := target.Identifier.(*Identity)
			h.auth.Ban(id.PublicKey(), until)
			h.auth.BanAddr(id.RemoteAddr(), until)

			body := fmt.Sprintf("%s was banned by %s.", target.Name(), msg.From().Name())
			room.Send(message.NewAnnounceMsg(body))
			target.Close()

			logger.Debugf("Banned: \n-> %s", id.Whois())

			return nil
		},
	})

	c.Add(chat.Command{
		Op:         true,
		Prefix:     "/motd",
		PrefixHelp: "[MESSAGE]",
		Help:       "Set a new MESSAGE of the day, print the current motd without parameters.",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			args := msg.Args()
			user := msg.From()

			h.mu.Lock()
			motd := h.motd
			h.mu.Unlock()

			if len(args) == 0 {
				room.Send(message.NewSystemMsg(motd, user))
				return nil
			}
			if !room.IsOp(user) {
				return errors.New("must be OP to modify the MOTD")
			}

			motd = strings.Join(args, " ")
			h.SetMotd(motd)
			fromMsg := fmt.Sprintf("New message of the day set by %s:", msg.From().Name())
			room.Send(message.NewAnnounceMsg(fromMsg + message.Newline + "-> " + motd))

			return nil
		},
	})

	c.Add(chat.Command{
		Op:         true,
		Prefix:     "/op",
		PrefixHelp: "USER [DURATION]",
		Help:       "Set USER as admin.",
		Handler: func(room *chat.Room, msg message.CommandMsg) error {
			if !room.IsOp(msg.From()) {
				return errors.New("must be op")
			}

			args := msg.Args()
			if len(args) == 0 {
				return errors.New("must specify user")
			}

			var until time.Duration = 0
			if len(args) > 1 {
				until, _ = time.ParseDuration(args[1])
			}

			member, ok := room.MemberByID(args[0])
			if !ok {
				return errors.New("user not found")
			}
			room.Ops.Add(set.Itemize(member.ID(), member))

			id := member.Identifier.(*Identity)
			h.auth.Op(id.PublicKey(), until)

			body := fmt.Sprintf("Made op by %s.", msg.From().Name())
			room.Send(message.NewSystemMsg(body, member.User))

			return nil
		},
	})
}

*/
