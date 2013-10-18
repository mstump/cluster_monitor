package main

// https://blogs.oracle.com/janp/entry/how_the_scp_protocol_works

import (
	"code.google.com/p/go.crypto/ssh"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"
)

const privateKey = `content of id_rsa`

type keychain struct {
	keys []ssh.Signer
}

func (k *keychain) Key(i int) (ssh.PublicKey, error) {
	if i < 0 || i >= len(k.keys) {
		return nil, nil
	}

	return k.keys[i].PublicKey(), nil
}

func (k *keychain) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
	return k.keys[i].Sign(rand, data)
}

func (k *keychain) add(key ssh.Signer) {
	k.keys = append(k.keys, key)
}

func (k *keychain) loadPEM(file string) error {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return err
	}
	k.add(key)
	return nil
}

func connectClient(host string, port uint, config *ssh.ClientConfig) (client *ssh.ClientConn, err error) {
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
}

func newClientConfig(user string, key *keychain) *ssh.ClientConfig {
	clientConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthKeyring(key),
		},
	}
	return clientConfig
}

func writePipeToChan(input io.Reader, outchan chan []byte) {
	go func() {
		defer close(outchan)

		for {
			var buf = make([]byte, 64)
			n, err := input.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Fatal(err)
			}
			outchan <- buf[0:n]
		}
	}()
}

func monitorServer(quit chan bool, clientConfig *ssh.ClientConfig, outchan chan []byte, errchan chan []byte, host string, port uint, command string) (err error) {
	client, err := connectClient(host, port, clientConfig)
	if err != nil {
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	writePipeToChan(stdout, outchan)
	writePipeToChan(stderr, errchan)

	if err := session.Start(command); err != nil {
		return err
	}

	result := make(chan error)
	go func() {
		result <- session.Wait()
	}()

	select {
	case err := <-result:
		return err
	case <-quit:
		session.Signal(ssh.SIGINT)
		session.Close()
		return nil
	}
}

type Configuration struct {
	outputDir     string
	hosts         []string
	hostsString   string
	port          uint
	duration      int64
	commandString string
	cpuProfile    string
	sshUser       string
	sshKeyPath    string
}

func NewConfiguration() *Configuration {
	return &Configuration{
		hosts:         make([]string, 0),
		hostsString:   "",
		port:          22,
		duration:      -1,
		outputDir:     "",
		commandString: "",
		sshUser:       "",
		sshKeyPath:    "",
		cpuProfile:    ""}
}

func parseArgs(config *Configuration) {
	flag.StringVar(&config.cpuProfile, "cpuprofile", "", "write cpu profile to file")
	flag.StringVar(&config.hostsString, "h", "", "Comma delimited list of hosts")
	flag.StringVar(&config.commandString, "c", "", "Command to execute")
	flag.StringVar(&config.outputDir, "o", "", "output directory")
	flag.StringVar(&config.sshKeyPath, "k", "", "ssh key")
	flag.StringVar(&config.sshUser, "u", "", "ssh user")
	flag.UintVar(&config.port, "p", 22, "SSH port")
	flag.Int64Var(&config.duration, "t", -1, "time to run (-1 is forever)")
	flag.Parse()

	if config.duration > 0 {
		config.duration = config.duration * time.Second.Nanoseconds()
	} else {
		config.duration = int64(^uint64(0) >> 1)
	}

	if config.hostsString != "" {
		config.hosts = strings.Split(config.hostsString, ",")
	}
}

func checkConfiguration(config *Configuration) error {
	if config.sshUser == "" {
		return errors.New("An ssh user was not specified")
	}

	if config.sshKeyPath == "" {
		return errors.New("An ssh key was not specified")
	}

	if config.commandString == "" {
		return errors.New("A command was not specified")
	}

	if len(config.hosts) == 0 {
		return errors.New("No host was specified")
	}

	if config.outputDir == "" {
		return errors.New("No output directory was specified")
	}

	return nil
}

func logChannel(done *sync.WaitGroup, quit chan bool, input chan []byte, path string) {
	go func() {
		outFile, err := os.Create(path)
		if err != nil {
			log.Fatal(err)
		}

		done.Add(1)
		defer func() {
			done.Done()
			if err := outFile.Close(); err != nil {
				log.Fatal(err)
			}
		}()

		for {
			select {
			case <-quit:
				return
			case data := <-input:
				outFile.Write(data)
			}
		}
	}()
}

func main() {
	config := NewConfiguration()
	parseArgs(config)
	err := checkConfiguration(config)
	if err != nil {
		log.Println(err)
		flag.Usage()
		os.Exit(1)
	}

	// set the max number of process
	goMaxProcs := os.Getenv("GOMAXPROCS")
	if goMaxProcs == "" {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	keychain := new(keychain)
	keychain.loadPEM(config.sshKeyPath)
	sshConfig := newClientConfig(config.sshUser, keychain)

	if config.cpuProfile != "" {
		f, err := os.Create(config.cpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	quit := make(chan bool)

	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		_ = <-signalChannel
		close(quit)
	}()

	err = os.MkdirAll(config.outputDir, 0700)
	if err != nil {
		log.Fatalf("%q: %s", config.outputDir, err)
	}

	var clientGroup sync.WaitGroup

	for _, host := range config.hosts {
		go func(host string) {
			log.Printf("connecting to %s\n", host)
			outchan := make(chan []byte)
			errchan := make(chan []byte)

			clientGroup.Add(1)
			defer clientGroup.Done()

			logChannel(&clientGroup, quit, outchan,
				path.Join(config.outputDir, fmt.Sprintf("%s_stdout.txt", host)))

			logChannel(&clientGroup, quit, errchan,
				path.Join(config.outputDir, fmt.Sprintf("%s_stderr.txt", host)))

			exitStatus := monitorServer(quit, sshConfig, outchan, errchan, host, config.port, config.commandString)
			exitString := "0"
			if exitStatus != nil {
				exitString = fmt.Sprintf("%s", err)
			}
			log.Printf("%s: %s", host, exitString)
		}(host)
	}

	startTime := time.Now()
	func() {
		for {
			select {
			case <-time.After(time.Second):
				if time.Now().Sub(startTime).Nanoseconds() > config.duration {
					close(quit)
					return
				}
			case <-quit:
				return
			}
		}
	}()

	clientGroup.Wait()
}
