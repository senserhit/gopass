package action

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gopasspw/gopass/internal/action/exit"
	"github.com/gopasspw/gopass/internal/out"
	"github.com/gopasspw/gopass/internal/tree"
	"github.com/gopasspw/gopass/pkg/ctxutil"
	"github.com/gopasspw/gopass/pkg/gopass/secrets"
	"github.com/urfave/cli/v2"
)

// Grep searches a string inside the content of all files.
func (s *Action) Grep(c *cli.Context) error {
	ctx := ctxutil.WithGlobalFlags(c)
	if !c.Args().Present() {
		return exit.Error(exit.Usage, nil, "Usage: %s grep arg", s.Name)
	}

	// get the search term.
	needle := c.Args().First()
	if c.Bool("ignore-case") {
		needle = strings.ToLower(needle)
	}

	haystack, err := s.Store.List(ctx, tree.INF)
	if err != nil {
		return exit.Error(exit.List, err, "failed to list store: %s", err)
	}

	fileTimes := make(map[string]time.Time)
	for _, v := range haystack {
		info, err := os.Stat(s.Store.Path() + "/" + v + ".gpg")
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		fileTimes[v] = info.ModTime()
	}

	// 按文件的修改时间进行排序
	sort.Slice(haystack, func(i, j int) bool {
		// 比较文件 i 和文件 j 的修改时间
		return fileTimes[haystack[i]].After(fileTimes[haystack[j]])
	})

	matchFn := func(haystack string) bool {
		if c.Bool("ignore-case") {
			haystack = strings.ToLower(haystack)
		}
		return strings.Contains(haystack, needle)
	}

	if c.Bool("regexp") {
		re, err := regexp.Compile(needle)
		if err != nil {
			return exit.Error(exit.Usage, err, "failed to compile regexp %q: %s", needle, err)
		}
		matchFn = re.MatchString
	}

	cache := make(map[string]string)
	cacheName := ".cache.5df83c78ea58fa2f7eb87e8085bea10c"
	cacheChanged := false
	if s.Store.Exists(ctx, cacheName) {
		sec, err := s.Store.Get(ctx, cacheName)
		if err != nil {
			out.Errorf(ctx, "failed to decrypt %s: %v", cacheName, err)
			return err
		}
		err = json.Unmarshal(sec.Bytes(), &cache)
		if err != nil {
			out.Errorf(ctx, "failed to unmarshal cache %s: %v", cacheName, err)
			return err
		}
	}

	var matches int
	var errors int

	for _, v := range haystack {
		if v == cacheName {
			break 
		} 
		sec, err := s.Store.Get(ctx, v)
		if err != nil {
			out.Errorf(ctx, "failed to decrypt %s: %v", v, err)
			errors++
			continue
		}
		cache[v] = string(sec.Bytes())
		cacheChanged = true
	}

	var keysToDelete []string

	for k, v := range cache {
		if _, ok := fileTimes[k]; !ok {
			keysToDelete = append(keysToDelete, k)
			continue
		}
		if matchFn(v) {
			out.Printf(ctx, "%s matches", color.BlueString(k))
			out.Printf(ctx, "%s", color.BlueString(v))
			matches++
		}
	}

	for _, k := range keysToDelete {
		delete(cache, k)
		cacheChanged = true
	}

	if cacheChanged {
		jsonData, _ := json.Marshal(cache)
		sec := secrets.NewAKV()
		sec.Write(jsonData)
		s.Store.Set(ctx, cacheName, sec)
	}

	if errors > 0 {
		out.Warningf(ctx, "%d secrets failed to decrypt", errors)
	}
	out.Printf(ctx, "\nScanned %d secrets. %d matches, %d errors", len(haystack), matches, errors)

	return nil
}
