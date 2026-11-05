---
title: "Istreams Pitfalls"
date: 2026-11-05 01:00:00 +00:00
layout: article
permalink: /technical/istream_pitfalls/
description: ""
categories: [tutorial, technical, white-paper]
tags: [tutorial, technical, white-paper, cplusplus, iostream, istream, streams, file-input, formatted-extraction, integer-extraction, new-line, end-of-file, white-space, integer-representation, error-handling, commentary]
author: "notweerdmonk"
draft: false
canonical_url: "https://notweerdmonk.github.io/technical/istream_pitfalls/"
---
# Pitfalls in C++ input streams

A post[^1] on a thread in a popular blog that is over twenty-one years old now,
but pertinent to this day, keeps the memories fresh of the times when learning
C++ was easier but unsystematic for yours truly; few personality quirks and
remnants of traits one persistently works towards rectifying, if not transform
in their entirety. It had become customary to stumble upon every once in while,
exploring the reaches of the web using the search engine(s), somewhat like an
avenue for pilgrimage.

## The problem: using `std::basic_ios::eof`

This is a snippet of C++ which reads integers from a file interpreted as text.

```cpp
#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
	if (argc < 2 || !argv[1]) {
		return -1;
	}
	std::ifstream file(argv[1]);
	if (file) {
		int i;
		// Incorrect
		while (!file.eof()) {
		    file >> i;
		    std::cout << i << ' ';
		}
		std::cout << std:: endl;
	}
	return 0;
}
```

The author points out that the above code will produce unwanted results if we
want to read a string of integers from a file. If we create file with a text
editor configured normally, there will be a new-line character at the end of the
line of integers.

```bash
$ cat sequence.txt
0 1 1 2 3 5 8 13 21 34 55
$ xxd -c 1 sequence.txt
00000000: 30  0
00000001: 20
00000002: 31  1
00000003: 20
00000004: 31  1
00000005: 20
00000006: 32  2
00000007: 20
00000008: 33  3
.
.
.
00000017: 35  5
00000018: 35  5
00000019: 0a  .
```

The problem of printing the last integer twice requires some commentary. The way
`std::basic_ios::eof` works is that it returns `true` only if an input/output
operation on the stream is unable to read data any further and the `eofbit` in
the stream state gets set. Read the previous statement carefully. In case of any
other stream error the function will return `false`. This induces a caveat.

In case of the above example the while loop checks for `file.eof()` after
reading the last integer but does not terminate the loop yet because there is
one character left to read. We try to read some integer again and print it. The
extraction operator (`>>`) of `std::ifstream` skips the new-line character and
fails to read any new value into the integer variable, which results in the
previously read value to be printed twice. This is not an error condition.

The `cat` program can be used to write to a file, avoiding the new-line
character. Ctrl-D[^2] (end-of-file) is used to conclude reading of input and
consequently writing to the file. This input sequence can also be used for
multi-line text input, and another method is to use a `heredoc` delimiter,
especially when `cat` is invoked from shell scripts. An important distinction
between these two methods is that terminating input using a `heredoc` delimiter
text always requires the `heredoc` to be entered on a new line and this would
terminate the file with a new-line character. The end-of-file condition however,
can be entered in continuation of any line of input.

```bash
$ cat > file2.txt
1 2 3
$ cat file2.txt
1 2 3
$ xxd -c 1 file2.txt
00000000: 31  1
00000001: 20
00000002: 32  2
00000003: 20
00000004: 33  3
```

Such inputs are not always possible and pose as more of an adjustment rather
than a proper solution.

Also, this does not address our concern of reading and parsing a string of
white-space separated integers completely. What if the file contains a string of
integers without trailing new-line character albeit one or more alphabets?
Consider `1 2 3a` or `1 2 3 a` for instance. We would have an infinite loop to
deal with as the extraction operator would keep trying to read an integral value
and fail.  This causes a stream error leading to `std::ios_base::failbit`
getting set and the integer variable being set to 0. But `std::ios_base::eofbit`
never gets set as some data is still left to be read in the stream, it just does
not match the expected format for extraction.

When the program keeps printing the read integer value, we have yet another way
to fill the terminal screen with zeroes indefinitely!

### Improvement: checking for `std::basic_ios::fail`

Instead of checking for `std::basic_ios::eof` we can check for
`std::basic_ios::fail`, which checks if either of `std::ios_base::failbit` or
`std::ios_base::badbit` is set. The `operator bool` for a stream derived from
`std::basic_ios` uses `std::basic_ios::fail` to return values which evaluates
to `true` if `fail()` returns `false` or `false` otherwise, in a Boolean
context. In older versions, the safe bool problem required `operator void*` to
be provided instead of the `operator bool`, which returns a null pointer if at
least one of `std::ios_base::failbit` or `std::ios_base::badbit` is set, and
some non-null value otherwise.

This enables using the stream object directly as a Boolean expression, checking
the Boolean complement of the `std::basic_ios::fail`. Even though the `fail()`
function does not check for `std::ios_base:eofbit`, it detects failures in
formatted extractions or errors in the underlying stream. This lets us handle
failure in extraction of integers using the input stream objects correctly when
the stream has not encountered the end-of-file condition.

**Using the stream object as a Boolean expression**

```cpp
#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
	if (argc < 2 || !argv[1]) {
		return -1;
	}
	std::ifstream file(argv[1]);
	if (file) {
		int i;
		while (file) {
			file >> i;
			std::cout << i << ' ';
		}
		std::cout << std::endl;
	}
	return 0;
}
```

The extraction operator itself can also be used as a Boolean expression because
the `operator>>` returns `*this`. But this progresses the loop conditional to
the point of failure of extraction from the stream object and avoids consumption
of erroneous values, which is the case in the previous solution. The state of
the steam is modified to set the `std::ios_base::failbit` when either
a non-integral literal or a new-line characters is encountered, without the
actual end-of-file condition being satisfied for the stream. Consequently we are
able to detect failures accurately.

**Using the extraction operator as a Boolean expression**

```cpp
#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
	if (argc < 2 || !argv[1]) {
		return -1;
	}
	std::ifstream file(argv[1]);
	if (file) {
		int i;
		while (file >> i) {
			std::cout << i << ' ';
		}
		std::cout << std:: endl;
	}
	return 0;
}
```

Such an approach however, does not cover all possibilities, as we shall elucidate
later on. Particularly when the strings being read by the input stream may not
entirely represent an integral value.

### Ideal solution: querying 1std::ios_base::eofbit`

Consider a scenario when there are three strings with leading and trailing
white-space `"   123   "`, `"   456"` and `"   1ab   "` and each one of them
needs to be tested for representation of an integer in its entirety. An object
of the `std::istringstream` type can be utilized that encapsulates a string and
provides an abstraction of the `std::basic_istream` type to interact with. This
is similar to the usage of a `std::ifstream` object to extract values from a
file on disk.

```cpp
#include <sstream>

std::istringstream iss{"   123   "};
int value;

if (iss >> value) {
	std::cout << value << std::endl;
} else {
	std::cerr << "Not an integer" << std::endl;
}
```

The trivial approach stated above will extract the integer `123` from the first
string and integer `456` from the second; leading white-space are skipped over
by the extraction operator. Trailing white-space if present have no impact
however.  In case of the third the string, the extraction will not fail but
extract just the `1` and stop as the alphabets do not satisfy the expected
extraction type that is an `int`. If we had a string such as "   123abc45", this
approach will still succeed and store `123` in the provided `int` variable,
which refutes the criterion for the integer representation test to pass. The
extraction operator accepts the syntax for integer, including a leading sign; it
succeeds until any other non-integral character is encountered or if the sign
character is not trailed by at least one digit. The returned value is an integer
while the entire string itself is not an integer. The end-of-file condition of
the `std::basic_istream` base class can be leveraged to ensure that the entire
string has been consumed by the extraction routine, making it certain all the
characters are either digits or a sign character followed by one or more digits,
with optional leading white-space; the string itself represents an integer,
under normal format settings and locale for the stream. Different
representations, the scientific notation for instance will require separate
handling.

With C++ iostreams, the aforementioned approach of additionally extracting
an integer followed by consumption of the trailing white-space characters, and
finally checking for the end-of-file condition, will result in the complete
expression to be evaluated as `true` when are no other characters traling an
integer with an optional sign character, can be implemented as mentioned next.
Any leading white-space are skipped by default during formatted extraction.

```cpp
std::istringstream iss{"   123   "};
int value;

if (
		iss >> value >> std::ws &&
		iss.get() == std::char_traits<char>::eof()
) {
		// Consume the extracted integer
} else {
		// Error or handle the entire string not being parsable as an integer
}
```

The following program uses the above source code to parse such representations
of integers from a file.

```cpp
#include <iostream>
#include <fstream>

int main(int argc, char *argv[]) {
	if (argc < 2 || !argv[1]) {
		return -1;
	}
	std::ifstream file(argv[1]);
	if (file) {
		int i;
		while (file >> i) {
			std::ifstream::int_type ch = file.get();
			if (
					file >> std::ws &&
					file.peek() == std::char_traits<char>::eof()
			) {
				std::cout << i << '\n';
			} else {
				std::cerr << "Not an integer\n";
			}
		}
	}
	return 0;
}
```

Two results are used here.

1. The first is the result of the formatted extraction operation on the
	 `std::istringstream` for an `int` variable followed by white-space.

2. The second result is comparison of the value returned by the
	 `std::istringstream::get` member function against the end-of-file condition
	 represented by `std::char_traits<char>::eof`, and expect it to succeed only
	 if the entire string has been consumed by the extraction operation and fail
	 otherwise if non-integral characters remain in the string.

An issue still exists that if an integer trailed by white-space is followed by
any other literal, integer or otherwise, the implementation is unable to parse
and provide the first valid integer representation. This happens because we
unconditionally discard white-space characters from the stream following the
successful formatted extraction of an integer, which may not correspond to the
actual representation of an integer, as we have discussed earlier.

It is necessary to fetch a single raw character from the stream, un-formatted of
course and check if it is a white-space character; the formatted extraction for
white-space (`std::ws`) returns the stream object even when no white-space
characters were discarded. The end-of-file condition for the stream is evaluated
as an union with the first expression, that is with a logical OR operator instead
of the logical AND operator as done previously. The earlier idea was to gobble
up trailing white-space and expect the stream to have reached its end (implying
it is unable to read input further, obviously). This enables us to discern an
integer trailed by white-space and then followed by any other literal as the end
as the entire expression evaluates to `true` either when there are white-space to
consume or the end-of-file condition has been reached.

The following program uses the above source code modified in a way to be able to
parse such representations with multiple valid integers separated by
white-space, and it does so while reading individual lines from a file.

```cpp
#include <iostream>
#include <fstream>
#include <sstream>

int main(int argc, char *argv[]) {
	if (argc < 2 || !argv[1]) {
		return -1;
	}
	std::ifstream file(argv[1]);
	if (file) {
		std::string line;
		while (std::getline(file, line)) {
			int i;
			std::istringstream iss{line};
			while (iss >> i) {
				if (
						(std::isspace(iss.peek()) && iss >> std::ws) ||
						iss.peek() == std::char_traits<char>::eof()
				) {
						std::cout << i << '\n';
				} else {
					std::cerr << "Not an integer\n";
				}
			}
		}
	}
	return 0;
}
```


## Error handling

Some pointers on handling error conditions on input/output streams are listed
next.

- **Exceptions for `eofbit`, `badbit`, and `failbit` conditions**

		Enabling the stream objects to throw exceptions for `eofbit`, `badbit`, and
		`failbit` conditions and wrapping their usage in a `try...catch` block
		provides a convenient and controlled way to detect and gracefully handle
		error conditions on the streams.

		Upon successfully catching an exception thrown by the stream, in order to
		continue using the stream further, its error state needs to be cleared by
		calling `std::basic_ios::clear` with `std::ios_base::goodbit` as its
		argument, which is also the default value. Clearing the state alone does not
		resolve the underlying cause of failure. The input sequence which caused
		failure for the stream needs to be cleared to avoid subsequent failures upon
		extraction or access, as mentioned later on in the text.

- **Manipulation of stream state**

		Apart from clearing the error state flags with `std::ios_base::goodbit` as
		the default argument value, `std::basic_ios::clear` is also used to set
		error state. It modifies the stream state with the desired state bit as the
		argument. If the same bit has been set using `std::basic_ios::exceptions`,
		an exception of type `std::ios_base::failure` is thrown. This results in the
		error message with `std::ios_base::clear` in it. `std::ios_base::badbit` is
		set when there is any irrecoverable error associated with the stream.
		`std::ios_base::failbit` is set when there is any formatting or extraction
		error associated with the stream leading to failures in input or output.
		`std::ios_base::eofbit` is set when the end-of-file condition is met for the
		stream which is mostly when the associated input source reaches its end,
		that is no further reads are possible under normal conditions.

- **Sanitizing the input upon error condition**

		The input sequence which resulted in an error condition for the stream,
		needs to be skipped to avoid repetition of the error when the stream is read
		again. This is achieved using `std::basic_istream::ignore` for input
		streams. It discards a number of characters until the delimiting character
		(inclusive) is encountered, both passed as arguments.

		Typically `std::numeric_limits<std::streamsize>::max` is passed as the
		first argument and the new-line character (`\n`) is passed as the second
		argument to `std::basic_istream::ignore` in order to consume all
		characters until and including the new-line character from the input source
		of the stream; this call for instance
		`std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n')`.

		If the input stream is associated with the standard input (`std::cin`), and 
		the `std::ios_base::eofbit` gets set due to the end-of-file condition on the
		input stream, simply calling `std::basic_istream::ignore` in order to
		consume and discard the erroneous input from the stream will throw the
		exception again as the end-of-file state has not been cleared.

		Note that a call to `std::cin.ignore` will also consume all characters
		until and including a leftover new-line character from the C standard input
		stream `stdio`.

## Ephemeral ponds

Indeed, it is established that simple approaches are often proven to be the best
to pass on knowledge effectively; message boards, discussion forums, chat
servers and blogs, all inclusively serve the purpose to inculcate practical
knowledge about a programming language, at least its usage; in contrast to
elaborate write-ups, courses and educational programs, which unequivocally are
foremost for rigor and cementing of fundamentals and pedagogic concepts. There
has been a dramatic transition with the onset of the age of language-model
driven search and text or source code generation. Utilization of such artificial
intelligence has eased this pursuit, yet also riddled it with another trivial
but definite layer nonetheless; that is, human inference, judgment and
capability to process information and reason.

---

A `bash` function to help fill a text file with space separated sequence
of integers is provided. Caution is advised when using larger inputs.

```bash
$ fibo() {
>   [[ $# -eq 0 || $1 -le 0 ]] && echo 0 || {
>       [[ $1 -eq 1 ]] && echo 1 || \
>         echo $(($(fibo $(($1 - 1))) + $(fibo $(($1 - 2)))))
>   }
> }
$
```


[^1]: [C and C++ Timesaving Tips - DaniWeb](https://www.daniweb.com/posts/jump/155265)
[^2]:
	Normally terminals employ the `read()` system call to read from the
	pseudo-terminal device, Ctrl-D is required to be pressed twice, that is to
	signal the terminal driver to register an end-of-file character (`VEOF`)
	twice, in the terminal's canonical mode. The first end-of-file condition
	causes the terminal driver to feed all the text which has been input on the
	current line, to the waiting `read()` system call. Therefore, `read()` does
	not return zero, that is the number of bytes read from the provided file
	descriptor to its caller. The program `cat` continues reading more bytes with
	subsequent call to `read()`. On a new line when no characters have been input,
	the end-of-file condition for the terminal driver does not feed any bytes to
	the waiting `read()` call, causing it to return zero. This causes the program
	to detect an end-of-file condition and completely stop reading any input.
