package SftpClient

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/gofrs/flock"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const BufferSize = 1024

/**
 * Addr : IP address or FQDN of SFTP server
 * Port : SFTP port
 * User : User to log in SFTP server
 * RemotePath : SFTP Path containing folder and files tree to access
 * RsaKeyFile : Absolute path to the local RSA key used for 'User' log in
 */
type SftpClient struct {
	addr, port, user, remotePath, rsaKeyFile string
	checkHostKey                             bool
	client                                   *sftp.Client
}

/*
 * SetPath allows to pass a different SFTP path than given during New instanciation
 */
func (c *SftpClient) SetPath(path string) {
	(*c).remotePath = path
}

/**
 * New etablish the connection and instanciate the new SFTP client
 * check the host key in ~/.ssh/known_hosts if checkhostkey is true
 * Return a SftpClient struct
 */
func New(addr, port, user, remotepath, rsakey string, checkhostkey bool) (*SftpClient, error) {
	var sc SftpClient
	sc.addr = addr
	sc.user = user
	sc.port = port
	sc.remotePath = remotepath
	sc.rsaKeyFile = rsakey
	sc.checkHostKey = checkhostkey
	key, err := ioutil.ReadFile(sc.rsaKeyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}

	var hostKey ssh.PublicKey
	var clbk ssh.HostKeyCallback
	if sc.checkHostKey {
		hostKey, err = getHostKey(sc.addr)
		if err != nil {
			return nil, fmt.Errorf("unable to get host key: %v", err)
		}
		clbk = ssh.FixedHostKey(hostKey)
	} else {
		clbk = ssh.InsecureIgnoreHostKey()
	}

	config := &ssh.ClientConfig{
		User: sc.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: clbk,
	}

	sshClient, err := ssh.Dial("tcp", sc.addr+":"+sc.port, config)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to SFTP server: %v", err)
	}

	sc.client, err = sftp.NewClient(sshClient)
	if err != nil {
		return nil, fmt.Errorf("unable to instanciate SFTP client: %v", err)
	}
	return &sc, nil
}

/*
 * Close closes the SFTP connection
 */
func (c *SftpClient) Close() {
	(*c.client).Close()
}

/*
 * Read the SFTP dir defined in var (*c).remotePath and return a slice containing all file names
 */
func (c *SftpClient) ListFiles() ([]string, error) {
	ls, err := (*c).client.ReadDir((*c).remotePath)
	if err != nil {
		return nil, fmt.Errorf("unable to read sftp dir: %v", err)
	}

	var fileList []string
	for _, elem := range ls {
		fileList = append(fileList, elem.Name())
	}
	return fileList, nil
}

/*
 * GetFiles retrives all files passed in the "fileList" slice
 * Return a slice containing the local absolute name of downloaded files
 */
func (c *SftpClient) GetFiles(fileList []string) ([]string, error) {
	var localFiles []string
	for _, filename := range fileList {
		//if strings.HasSuffix(filename, ".tgz") {
		//re := regexp.MustCompile(`.tgz$`)
		//filenameShort := string(re.ReplaceAll([]byte(filename), []byte{}))

		//fmt.Printf("-- Retrieve file %v\n", filename)

		//- Retrieve files
		sftpFile, err := (*c.client).Open(filepath.Join((*c).remotePath, filename))
		if err != nil {
			return nil, fmt.Errorf("unable to open sftp file: %v", err)
		}
		defer sftpFile.Close()

		fileStat, err := sftpFile.Stat()
		if err != nil {
			return nil, fmt.Errorf("unable to stat sftp file: %v", err)
		}
		fileSize := fileStat.Size()

		//- Reading from sftpFile
		//fmt.Printf("   reading %vB from %v\n", fileSize, filename)
		var fileContent = make([]byte, fileSize)
		sftpFile.Read(fileContent)

		tmpDir, err := ioutil.TempDir("", path.Base(filename))
		if err != nil {
			return nil, fmt.Errorf("unable to create temp dir: %v", err)
		}
		//defer os.RemoveAll(tmpDir)

		localName := filepath.Join(tmpDir, filename)
		localFile, err := os.OpenFile(localName, os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return nil, fmt.Errorf("unable to open local archive file: %v", err)
		}
		fmt.Printf("   writing file %v\n", localName)
		n, err := localFile.Write(fileContent)
		if int64(n) != fileSize {
			return nil, fmt.Errorf("Local file not fully written")
		} else if err != nil {
			return nil, fmt.Errorf("write error: ", err)
		}
		localFiles = append(localFiles, localName)
	}
	return localFiles, nil
}

/*
 * Put all files contained in fileList to SFTP server, in c.remotePath path
 * Each fileList item must be the local absolute file name
 */
func (c *SftpClient) PutFiles(fileList []string) error {
	for _, file := range fileList {
		//- Open local file
		fileLock := flock.New(file)
		locked, err := fileLock.TryLock()
		if err != nil {
			return fmt.Errorf("unable to lock file: ", err)
		}
		if locked {
			f, err := os.Open(file)
			if err != nil {
				fmt.Errorf("unable to open file to push on SFTP server: %v", err)
			}

			//- Create SFTP file
			filename := (*c).remotePath + "/" + path.Base(file)
			sf, err := (*c).client.Create(filename)
			if err != nil {
				fmt.Errorf("unable to create SFTP file: %v", err)
			}

			//- Read chunck of data and write it into SFTP until EOF
			buf := make([]byte, BufferSize)
			for {
				i, err := f.Read(buf)
				if err != nil {
					if err == io.EOF {
						break
					}
					fmt.Errorf("unable to read local data: %v", err)
				}

				buf = buf[:i]
				_, err = sf.Write(buf)
				if err != nil {
					fmt.Errorf("unable to write SFTP data: %v", err)
				}
			}
			fileLock.Unlock()
		}
	}
	return nil
}

func getHostKey(host string) (ssh.PublicKey, error) {
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, errors.New(fmt.Sprintf("error parsing %q: %v", fields[2], err))
			}
			break
		}
	}

	if hostKey == nil {
		return nil, errors.New(fmt.Sprintf("no hostkey for %s", host))
	}
	return hostKey, nil
}
