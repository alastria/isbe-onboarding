// Package sqlogger provides a custom slog.Handler that logs to a SQLite database and standard output.
package sqlogger

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gofiber/fiber/v2"
	_ "github.com/mattn/go-sqlite3"
)

const maxSizeLiveLog = 50000
const numLogFiles = 7

const logFileBasename = "logs"
const logFileExtension = "sqlite"

const openLogSQL = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS entries (
  epoch_secs LONG,
  nanos INTEGER, 
  level INTEGER,  
  content BLOB
);
`
const resetLogSQL = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;

DROP TABLE IF EXISTS entries;

CREATE TABLE IF NOT EXISTS entries (
  epoch_secs LONG,
  nanos INTEGER, 
  level INTEGER,  
  content BLOB
);
`

// groupOrAttrs holds either a group name or a list of slog.Attrs.
type groupOrAttrs struct {
	group string      // group name if non-empty
	attrs []slog.Attr // attrs if non-empty
}

type SQLogHandler struct {
	mutex         *sync.Mutex
	db            *sql.DB
	opts          Options
	goas          []groupOrAttrs
	currentName   string
	currentLogId  int
	lastInsertId  int64
	stdLogHandler slog.Handler
	cwd           string
	logDir        string
}

type SQLogHandlerInterface interface {
	slog.Handler
	Retrieve(numEntries int) ([]LogRecord, error)
}

type Options struct {
	// Level reports the minimum level to log.
	// Levels with lower levels are discarded.
	// If nil, the Handler uses [slog.LevelInfo].
	Level slog.Leveler

	NoColor bool

	// LogDir specifies the directory where log files will be stored.
	// If empty, the current working directory is used.
	LogDir string
}

func NewSQLogHandler(opts *Options) (*SQLogHandler, error) {

	h := &SQLogHandler{}

	if opts != nil {
		h.opts = *opts
	}

	// Use Info level by default if not set
	if h.opts.Level == nil {
		h.opts.Level = slog.LevelInfo
	}

	// The log files are stored in the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get the working directory: %w", err)
	}
	h.cwd = cwd

	h.stdLogHandler = slog.Default().Handler()

	// Determine the log directory
	logDir := h.opts.LogDir
	if logDir == "" {
		logDir = h.cwd
	} else {
		// If a relative path is provided, join it with the current working directory
		if !filepath.IsAbs(logDir) {
			logDir = filepath.Join(h.cwd, logDir)
		}
	}

	// Ensure the log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}
	h.logDir = logDir

	// Look at the current directory and determine the current log file name
	currentName, err := determineCurrentNameOnStartup(h.logDir)
	if err != nil {
		return nil, err
	}
	h.currentName = currentName

	db, err := sql.Open("sqlite3", filepath.Join(h.logDir, h.currentName))
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(openLogSQL)
	if err != nil {
		return nil, err
	}

	h.db = db
	h.mutex = &sync.Mutex{}

	color.NoColor = h.opts.NoColor

	return h, nil

}

func determineCurrentNameOnStartup(logDir string) (string, error) {

	// Read all entries in the current directory
	dirEntry, err := os.ReadDir(logDir)
	if err != nil {
		return "", err
	}

	var candidateFileName string
	candidateLogNumber := 0
	greatestModificationTime := int64(0)

	for _, currentEntry := range dirEntry {
		// Skip entries which are directories and handle only files
		if currentEntry.IsDir() {
			continue
		}

		// Skip files with a name not according to the pattern name.aNumber.extension
		parts := strings.Split(currentEntry.Name(), ".")
		if len(parts) != 3 {
			continue
		}

		// Skip files without the exact name and extension
		if parts[0] != logFileBasename || parts[2] != logFileExtension {
			continue
		}

		// We found a log file, check its modification time against the current minimum
		currentEntryInfo, err := currentEntry.Info()
		if err != nil {
			return "", err
		}

		currentModificationTime := currentEntryInfo.ModTime().Unix()

		if currentModificationTime < greatestModificationTime {
			continue
		}

		currentEntryLogNumber, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", err
		}

		if currentModificationTime > greatestModificationTime {
			greatestModificationTime = currentModificationTime
			candidateFileName = currentEntry.Name()
			candidateLogNumber = currentEntryLogNumber
			continue
		}

		// We will account for the very strange case where two log files have the same modification time
		// We will choose the one with greater log number or when the current entry number is 0 and
		// the candidate is numLogFiles-1

		if (currentEntryLogNumber > candidateLogNumber) || (currentEntryLogNumber == 0 && candidateLogNumber == numLogFiles-1) {
			greatestModificationTime = currentModificationTime
			candidateFileName = currentEntry.Name()
			candidateLogNumber = currentEntryLogNumber
		}

	}

	// If we are starting the first time, we would not find any files complying with the naming
	if candidateFileName == "" {
		return fmt.Sprintf("%s.%d.%s", logFileBasename, 0, logFileExtension), nil
	} else {
		return candidateFileName, nil
	}
}

// rotate closes the current log database, increments the log ID, and opens a new log database.
// If the log ID reaches the maximum number of log files, it wraps around to 0.
// It also creates the necessary table in the new database.
// It assumes that the database handle is already locked by the caller.
func (h *SQLogHandler) rotate() error {
	// Close the current log database
	h.db.Close()

	// Increment the log ID
	h.currentLogId++
	if h.currentLogId >= numLogFiles {
		h.currentLogId = 0
	}

	// Get the next file name
	h.currentName = fmt.Sprintf("%s.%d.%s", logFileBasename, h.currentLogId, logFileExtension)
	fmt.Println("rotating log file", "name", h.currentLogId)

	// Open the new log database
	db, err := sql.Open("sqlite3", filepath.Join(h.logDir, h.currentName))
	if err != nil {
		return err
	}

	// Create the table
	_, err = db.Exec(resetLogSQL)
	if err != nil {
		return err
	}

	h.db = db

	return nil
}

func (h *SQLogHandler) Name() string {
	return "SQLogger"
}

func (h *SQLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *SQLogHandler) Level() *slog.LevelVar {
	return h.opts.Level.(*slog.LevelVar)
}

func (h *SQLogHandler) Handle(c context.Context, r slog.Record) error {

	// Get a byte buffer from the pool and defer returning it to the pool
	bufp := allocBuf()
	bufColor := *bufp
	defer func() {
		*bufp = bufColor
		freeBuf(bufp)
	}()

	bufp2 := allocBuf()
	bufPlain := *bufp2
	defer func() {
		*bufp2 = bufPlain
		freeBuf(bufp2)
	}()

	// We do not follow the usual rule for handlers of ignoring empty timestamp
	// We need the timestamp for the database
	if r.Time.IsZero() {
		r.Time = time.Now()
	}

	const glevel = 130
	greyColor := color.RGB(glevel, glevel, glevel)

	// The string representation of the log time
	logTime := r.Time.Format(time.TimeOnly)
	logTimeColored := greyColor.Sprint(logTime)

	// Color the level and set minimum length of 5 chars
	level := r.Level.String()

	coloredLevel := level
	coloredMessage := r.Message
	switch r.Level {
	case slog.LevelDebug:
		coloredLevel = color.MagentaString(level)
	case slog.LevelInfo:
		coloredLevel = color.GreenString(level)
	case slog.LevelWarn:
		coloredLevel = color.HiYellowString(level)
		coloredMessage = color.HiYellowString(r.Message)
	case slog.LevelError:
		coloredLevel = color.RedString(level)
		coloredMessage = color.RedString(r.Message)
	}

	var undecoratedLocation string
	var decoratedLocation string

	// The location of the log call
	if r.PC != 0 {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()

		dir, file := filepath.Split(f.File)

		// Trim the root directory prefix to get the relative directory of the source file
		var fullFileName string
		relativeDir, err := filepath.Rel(h.cwd, filepath.Dir(dir))
		if err != nil {
			fullFileName = f.File
		} else {
			fullFileName = filepath.Join(relativeDir, file)
		}

		undecoratedLocation = fmt.Sprintf("%s:%d", fullFileName, f.Line)
		decoratedLocation = color.BlueString(undecoratedLocation)

	}

	// *******************************************
	// timestamp
	// *******************************************
	bufColor = append(bufColor, logTimeColored...)
	bufColor = append(bufColor, ' ')

	bufPlain = append(bufPlain, logTime...)
	bufPlain = append(bufPlain, ' ')

	// *******************************************
	// level
	// *******************************************
	bufColor = append(bufColor, coloredLevel...)
	bufColor = append(bufColor, ' ')
	if len(level) < 5 {
		bufColor = append(bufColor, ' ')
	}

	bufPlain = append(bufPlain, level...)
	bufPlain = append(bufPlain, ' ')
	if len(level) < 5 {
		bufPlain = append(bufPlain, ' ')
	}

	// *******************************************
	// location
	// *******************************************

	if !strings.HasPrefix(r.Message, "=>") && !strings.HasPrefix(r.Message, "<=") {
		bufColor = append(bufColor, decoratedLocation...)
		bufColor = append(bufColor, ' ')

		bufPlain = append(bufPlain, undecoratedLocation...)
		bufPlain = append(bufPlain, ' ')

	}

	// *******************************************
	// message
	// *******************************************

	bufColor = append(bufColor, coloredMessage...)
	bufColor = append(bufColor, ' ')

	bufPlain = append(bufPlain, r.Message...)
	bufPlain = append(bufPlain, ' ')

	// *******************************************
	// *******************************************

	// Handle state from WithGroup and WithAttrs.
	goas := h.goas
	if r.NumAttrs() == 0 {
		// If the record has no Attrs, remove groups at the end of the list; they are empty.
		for len(goas) > 0 && goas[len(goas)-1].group != "" {
			goas = goas[:len(goas)-1]
		}
	}

	for _, goa := range goas {
		if goa.group != "" {
			bufColor = fmt.Appendf(bufColor, "%s ", goa.group)
		} else {
			for _, a := range goa.attrs {
				bufColor = h.appendAttr(bufColor, a, greyColor)
			}
		}
	}

	r.Attrs(func(a slog.Attr) bool {
		bufColor = h.appendAttr(bufColor, a, greyColor)
		return true
	})

	bufColor = append(bufColor, '\n')
	bufPlain = append(bufPlain, '\n')

	// Print the colored buffer to standard output as a normal log
	// fmt.Println(string(bufColor))
	os.Stdout.Write(bufColor)

	// *************************************************************
	// We now insert a record in the database
	// *************************************************************

	h.mutex.Lock()
	defer h.mutex.Unlock()

	stmt, err := h.db.Prepare("insert into entries (epoch_secs, nanos, level, content) values(?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	result, err := stmt.Exec(r.Time.Unix(), r.Time.Nanosecond(), r.Level, string(bufPlain))
	if err != nil {
		return fmt.Errorf("inserting log record: %w", err)
	}

	// Check if the current log file has reached the maximum number of entries, and rotate the log if so
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("retrieving last insert id: %w", err)
	}
	h.lastInsertId = id

	if h.lastInsertId >= maxSizeLiveLog {
		h.rotate()
	}

	return nil
}

type LogRecord struct {
	Seconds int64
	Nanos   int32
	Level   string
	Content string
}

const queryLogSQL = `
SELECT epoch_secs, nanos, level, content FROM entries ORDER BY rowid DESC, nanos DESC LIMIT ? OFFSET ?`

const maxEntries = min(1000, maxSizeLiveLog)

// Retrieve returns up to numEntries most recent LogRecord entries from the log handler.
// If there are fewer than numEntries available, all available entries are returned.
// Returns a slice of LogRecord and an error if retrieval fails.
func (h *SQLogHandler) Retrieve(numEntries int) ([]LogRecord, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if numEntries > maxEntries {
		return nil, fmt.Errorf("number of entries requested (%d) exceeds maximum allowed (%d)", numEntries, maxEntries)
	}

	stmt, err := h.db.Prepare(queryLogSQL)
	if err != nil {
		return nil, fmt.Errorf("preparing log query: %w", err)
	}
	defer stmt.Close()

	rows, err := stmt.Query(numEntries, 0)
	if err != nil {
		return nil, fmt.Errorf("querying log records: %w", err)
	}
	defer rows.Close()

	var logRecords []LogRecord

	for rows.Next() {
		var epochSecs int64
		var nanos int32
		var level int
		var content []byte

		err = rows.Scan(&epochSecs, &nanos, &level, &content)
		if err != nil {
			return nil, fmt.Errorf("scanning log record: %w", err)
		}

		levelString := slog.Level(level).String()

		logRecords = append(logRecords, LogRecord{
			Seconds: epochSecs,
			Nanos:   nanos,
			Level:   levelString,
			Content: string(content),
		})
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating log records: %w", err)
	}

	return logRecords, nil

}

func (h *SQLogHandler) withGroupOrAttrs(goa groupOrAttrs) *SQLogHandler {
	h2 := *h
	h2.goas = make([]groupOrAttrs, len(h.goas)+1)
	copy(h2.goas, h.goas)
	h2.goas[len(h2.goas)-1] = goa
	return &h2
}

func (h *SQLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return h.withGroupOrAttrs(groupOrAttrs{attrs: attrs})
}

func (h *SQLogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return h.withGroupOrAttrs(groupOrAttrs{group: name})
}

func (h *SQLogHandler) Close() {
	if h.db == nil {
		return
	}
	h.db.Close()
}

func (h *SQLogHandler) appendAttr(buf []byte, a slog.Attr, keyColor *color.Color) []byte {
	// Resolve the Attr's value before doing anything else.
	a.Value = a.Value.Resolve()
	// Ignore empty Attrs.
	if a.Equal(slog.Attr{}) {
		return buf
	}
	switch a.Value.Kind() {
	case slog.KindString:

		buf = fmt.Appendf(buf, "%s%q ", keyColor.Sprint(a.Key+"="), a.Value.String())

	case slog.KindTime:
		// Write times in a standard way, without the monotonic time.
		if a.Key == slog.TimeKey {
			buf = fmt.Appendf(buf, "%s ", a.Value.Time().Format(time.RFC3339Nano))
			break
		}

		buf = fmt.Appendf(buf, "%s%s ", keyColor.Sprint(a.Key+"="), a.Value.Time().Format(time.RFC3339Nano))
	case slog.KindGroup:
		attrs := a.Value.Group()
		// Ignore empty groups.
		if len(attrs) == 0 {
			return buf
		}
		for _, ga := range attrs {

			if a.Key != "" {
				buf = fmt.Appendf(buf, "%s.", a.Key)
			}

			buf = h.appendAttr(buf, ga, keyColor)
		}
	default:
		if a.Key == slog.LevelKey {
			buf = fmt.Appendf(buf, "%s ", a.Value.String())
			break
		}
		buf = fmt.Appendf(buf, "%s%s ", keyColor.Sprint(a.Key+"="), a.Value)
	}
	return buf
}

var noLoggingFor = map[string]bool{
	"/health":      true,
	"/favicon.ico": true,
}

// FiberRequestLogger logs HTTP requests on entry and exit
func FiberRequestLogger(c *fiber.Ctx) error {

	// Log entry, except the /health request, to keep logs clean
	if _, found := noLoggingFor[c.Path()]; !found {
		slog.Debug("=> "+c.Method()+" "+c.Path(), slog.String("ip", c.IP()), slog.String("request_id", c.Get("X-Request-Id")))
	}

	// Go to next middleware
	if err := c.Next(); err != nil {
		return err
	}

	// Log exit
	code := c.Response().StatusCode()

	if code >= 500 {
		// Internal server errors
		meth := fmt.Sprintf("<= %s %d %s", c.Method(), code, c.Path())
		slog.Error(meth, slog.Int("status", code), slog.String("ip", c.IP()))
	} else if code >= 400 {
		// Caller errors
		meth := fmt.Sprintf("<= %s %d %s", c.Method(), code, c.Path())
		slog.Warn(meth, slog.Int("status", code), slog.String("ip", c.IP()))
	} else {
		// The rest
		if _, found := noLoggingFor[c.Path()]; !found {
			meth := fmt.Sprintf("<= %s %d %s", c.Method(), code, c.Path())
			slog.Debug(meth, slog.Int("status", code), slog.String("ip", c.IP()))
		}
	}

	return nil

}

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1024)
		return &b
	},
}

func allocBuf() *[]byte {
	return bufPool.Get().(*[]byte)
}

func freeBuf(b *[]byte) {
	// To reduce peak allocation, return only smaller buffers to the pool.
	const maxBufferSize = 16 << 10
	if cap(*b) <= maxBufferSize {
		*b = (*b)[:0]
		bufPool.Put(b)
	}
}

func Err(err error) slog.Attr {
	return slog.Any("err", err)
}
