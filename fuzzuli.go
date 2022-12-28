package main

import (
	"bufio"
	"fmt"
	"github.com/projectdiscovery/goflags"
	"log"
	"os"
	"regexp"
	"strings"
)

var urls, paths, methods []string

var options *Options
var extensions = []string{".rar", ".zip", ".tar.gz", ".tar", ".gz", ".jar", ".7z", ".bz2", ".sql", ".backup", ".war", ".bak", ".dll"}

var mime_types = []string{
	"application/octet-stream",
	"application/x-bzip",
	"application/x-bzip2",
	"application/gzip",
	"application/java-archive",
	"application/vnd.rar",
	"application/x-sh",
	"application/x-tar",
	"application/zip",
	"application/x-7z-compressed",
	"application/x-msdownload",
	"application/x-msdos-program",
}

func main() {

	options = ParseOptions()

	if options.file != "" {
		readFromFile()
	} else {
		fi, _ := os.Stdin.Stat()
		if fi.Mode()&os.ModeNamedPipe == 0 {
			fmt.Println("[!] No data found in pipe. urls must given using pipe or f parameter!")
			os.Exit(1)
		} else {
			readFromStdin()
		}
	}

	if options.extension != "" {
		extensions = strings.Split(options.extension, ",")
	}

	if options.method == "all" {
		m := "regular,withoutdots,withoutvowels,reverse,mixed,withoutdv,shuffle"
		methods = strings.Split(m, ",")
	} else {
		methods = strings.Split(options.method, ",")
	}

	if options.paths != "/" {
		paths = strings.Split(options.paths, ",")
	} else {
		paths = strings.Split(options.paths, "")
	}

	for _, url := range urls {
		url := url

		start(url)

	}

}

func start(domain string) {
	var rgx = regexp.MustCompile(options.exclude)
	if len(domain) < options.domain_length+8 {
		if !rgx.MatchString(domain) {
			getAllCombination(domain)
		}
	}
}

func getAllCombination(domain string) {
	generate_wordlist := []string{}

	for _, method := range methods {
		switch method {
		case "regular":
			regularDomain(domain, &generate_wordlist)
		case "withoutdots":
			withoutDots(domain, &generate_wordlist)
		case "withoutvowels":
			withoutVowels(domain, &generate_wordlist)
		case "reverse":
			reverseDomain(domain, &generate_wordlist)
		case "mixed":
			mixedSubdomain(domain, &generate_wordlist)
		case "withoutdv":
			withoutVowelsAndDots(domain, &generate_wordlist)
		case "shuffle":
			shuffle(domain, &generate_wordlist)
		default:
			shuffle(domain, &generate_wordlist)
		}
	}

	for _, word := range generate_wordlist {
		headRequest(domain, word)
	}

}

func headRequest(domain string, word string) {
	for _, e := range extensions {
		for _, path := range paths {
			url := domain + path + options.prefix + word + options.suffix + e

			if options.print {
				// If the file doesn't exist, create it, or append to the file
				f, err := os.OpenFile(options.wFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					log.Fatal(err)
				}
				if _, err := f.Write([]byte(url + "\n")); err != nil {
					log.Fatal(err)
				}
				if err := f.Close(); err != nil {
					log.Fatal(err)
				}
			} else {
				fmt.Println(url)
			}
		}
	}
}

func regularDomain(domain string, wordlist *[]string) {
	generatePossibilities(domain, wordlist)
}

func withoutDots(domain string, wordlist *[]string) {
	without_dot := strings.ReplaceAll(domain, ".", "")
	generatePossibilities(without_dot, wordlist)
}

func withoutVowels(domain string, wordlist *[]string) {
	clear_vowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "")
	domain_without_vowel := clear_vowel.Replace(domain)
	generatePossibilities(domain_without_vowel, wordlist)
}

func withoutVowelsAndDots(domain string, wordlist *[]string) {
	clear_vowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "", ".", "")
	without_vowel_dot := clear_vowel.Replace(domain)
	generatePossibilities(without_vowel_dot, wordlist)
}

func mixedSubdomain(domain string, wordlist *[]string) {
	clear_domain := strings.Split(domain, "://")[1]
	split := strings.Split(clear_domain, ".")

	for sindex := range split {
		for eindex := range split {
			generatePossibilities("http://"+split[sindex]+"."+split[eindex], wordlist)
		}
	}
}

func reverseDomain(domain string, wordlist *[]string) {
	clear_domain := strings.Split(domain, "://")[1]
	split := strings.Split(clear_domain, ".")
	split_reverse := reverseSlice(split)
	reverse_domain := "http://" + strings.Join(split_reverse, ".")
	generatePossibilities(reverse_domain, wordlist)
	withoutDots(reverse_domain, wordlist)
	withoutVowels(reverse_domain, wordlist)
	withoutVowelsAndDots(reverse_domain, wordlist)
}

func shuffle(domain string, wordlist *[]string) {
	clear_domain := strings.Split(domain, "://")[1]
	split := strings.Split(clear_domain, ".")
	split_reverse := reverseSlice(split)
	reverse_domain := "http://" + strings.Join(split_reverse, ".")
	shuffleSubdomain(domain, wordlist)
	shuffleSubdomain(reverse_domain, wordlist)
}

func shuffleSubdomain(domain string, wordlist *[]string) {
	clear_domain := strings.Split(domain, "://")[1]
	splt := strings.Split(clear_domain, ".")
	for id1, _ := range splt {
		for id2, _ := range splt[id1:] {
			p := strings.Join(splt[id1:id1+id2+1], ".")
			addShuffleSubdomain(p, wordlist)
			if id2 >= 2 {
				p = splt[id1] + "." + splt[id1+id2]
				addShuffleSubdomain(p, wordlist)
			}
		}
	}
}

func addShuffleSubdomain(domain string, wordlist *[]string) {
	if !contains(*wordlist, domain) {
		*wordlist = append(*wordlist, domain)
	}

	clear_vowel := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "")
	domain_without_vowel := clear_vowel.Replace(domain)
	if !contains(*wordlist, domain_without_vowel) {
		*wordlist = append(*wordlist, domain_without_vowel)
	}

	without_dot := strings.ReplaceAll(domain, ".", "")
	if !contains(*wordlist, without_dot) {
		*wordlist = append(*wordlist, without_dot)
	}

	clear_voweldot := strings.NewReplacer("a", "", "e", "", "i", "", "u", "", "o", "", ".", "")
	without_vowel_dot := clear_voweldot.Replace(domain)
	if !contains(*wordlist, without_vowel_dot) {
		*wordlist = append(*wordlist, without_vowel_dot)
	}
}

func contains(slice []string, elements string) bool {
	for _, s := range slice {
		if elements == s {
			return true
		}
	}
	return false
}

func reverseSlice(slice []string) []string {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
}

func generatePossibilities(domain string, possibilities *[]string) {
	just_domain := strings.Split(domain, "://")[1]
	for first, _ := range just_domain {
		for last, _ := range just_domain[first:] {
			p := just_domain[first : first+last+1]
			if !contains(*possibilities, p) {
				*possibilities = append(*possibilities, p)
			}
		}
	}
}

func readFromStdin() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
}

func readFromFile() {
	file, err := os.Open(options.file)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
}

type Options struct {
	extension     string
	exclude       string
	replace       string
	method        string
	prefix        string
	suffix        string
	remove        string
	paths         string
	file          string
	wFileName     string
	domain_length int
	print         bool
	help          bool
}

func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`fuzzuli is a fuzzing tool that aims to find critical backup files by creating a dynamic wordlist based on the domain.`)

	createGroup(flagSet, "General Options", "GENERAL OPTIONS",
		flagSet.StringVar(&options.file, "f", "", "input file containing list of host/domain"),
		flagSet.StringVar(&options.paths, "pt", "/", "paths. separate with commas to use multiple paths. e.g. /,/db/,/old/"),
		flagSet.BoolVar(&options.print, "p", false, "writedown urls"),
		flagSet.StringVar(&options.wFileName, "wf", "logPath.txt", "output filename"),
	)

	createGroup(flagSet, "wordlist options", "WORDLIST OPTIONS",
		flagSet.StringVar(&options.method, "mt", "", "methods. avaible methods: regular, withoutdots, withoutvowels, reverse, mixed, withoutdv, shuffle"),
		flagSet.StringVar(&options.suffix, "sf", "", "suffix"),
		flagSet.StringVar(&options.prefix, "pf", "", "prefix"),
		flagSet.StringVar(&options.extension, "ex", "", "file extension. default (rar, zip, tar.gz, tar, gz, jar, 7z, bz2, sql, backup, war)"),
		flagSet.StringVar(&options.replace, "rp", "", "replace specified char"),
		flagSet.StringVar(&options.remove, "rm", "", "remove specified char"),
	)

	createGroup(flagSet, "domain options", "DOMAIN OPTIONS",
		flagSet.StringVar(&options.exclude, "es", "#", "exclude domain that contains specified string or char. e.g. for OR operand google|bing|yahoo"),
		flagSet.IntVar(&options.domain_length, "dl", 40, "match domain length that specified."),
	)

	_ = flagSet.Parse()

	return options
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
