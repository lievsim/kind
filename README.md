# Kind

Kind Is Not a Database. It's rather a kind and secure password manager for power users.

## Installation

In order to compile the `kind` executable, you'll need the *libsodium* library. See the [Compilation on Unix-like systems](https://download.libsodium.org/doc/installation) from the Libsodium documentation to install libsodium properly on Unix systems.

Running `make` in the `kind` directory will compile the program for your system. Running `make install` as super user will copy the executable under `/usr/local/bin`. Make sure that it's in your `PATH` in order to use `kind`. The install target will also create the `$HOME/.kind` folder where will be located the database.

```text
user@host:~ git clone git@github.com:lievsim/kind.git
user@host:~ cd kind
user@host:~ make
user@host:~ sudo make install
```

## Usage

Run `kind` to launch the program.

```text
user@host:~ kind
```

When running `kind` for the first time, you'll be prompted to define a master password for your database. The database is a *.csv* file stored under `$HOME/.kind/db.csv`.

```text
user@host:~ kind
Database not found under /home/lievsim/.kind/db.csv. Creating a new one...
Enter a master password: secret
```

In case a database is found under `$HOME/.kind/db.csv` you'll be asked for your master password. Upon successful login you'll be prompted with the command menu. The database is in **unlocked** state. The user can asks for passwords without having to re-type his master password.

```text
Master password: secret

[0] EXI: exists the program. 
[1] CLO: closes the database. 
[2] ADD: adds a password. 
[3] DEL: deletes a password. 
[4] SHW: shows a password. 
[5] CHP: changes the master password. 
[6] LST: lists all passwords. 
Enter a command [0-6]: 
```

From there you can type the following commands:

* **EXI**: exists the program safely, i.e. preventing partial writes and memory leaks.
* **CLO**: closes the database. The database is in **locked** state. You will have to re-type your master password to unlock the database.
* **ADD**: adds a password. You'll be prompted for an url and a password. After successfully adding a password you'll return to the command menu.
```text
Enter a command [0-6]: 2
URL: myurl
PWD: mypwd
```
* **DEL**: deletes a password. You'll be asked for an url. A message is shown to indicate if the entry was successfully removed or not. After deleting a password you'll return to the command menu.
```text
Enter a command [0-6]: 3
Enter an url: myurl
myurl was successfully removed
```
* **CHP**: changes the master password. You'll be prompted for your current master password. If your password is correct, you'll have to type your new password. If the operation is a success the database will be **locked** and you'll have to unlock it with your new password.
```text
Enter a command [0-6]: 5
Master password: test
Enter the new master password: secret
```
* **LST**: lists all entries in the database. Passwords are encrypted.
```text
Enter a command [0-6]: 6
myurl   N8sOeA5gtqRNvttm22xjsLeiwbaI3QqgpacNa8wtyeIuPajTMYkV3m6RmLweQvDqRXfׄ
myurl2  xgGH+CcpC/gdGq1YKqtooiy7sX9uBogEhiWk20XPhV65xJY3Dd93TLKQ3JyQP9PtRXfׄ
myurl3  3Q6f1jOgFWPD64tnJAbv7OX+aheCalIasUp2cbOXQvkgFYgYuXIFFNTYvWaEpXJ4RXf
```

## License

Kind is distributed under the MIT license. A copy of which can be found in the `LICENSE` file.

This project includes the work of Samuel Alexander (semitrivial) and its `csv_parser` under the MIT LICENSE. [https://github.com/semitrivial/csv_parser](https://github.com/semitrivial/csv_parser)

This project also includes the work of ryyst, a stack overflow user, author of the post [https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c](https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c?noredirect=1).

The Libsodium library cannot be re-licensed. It is distributed under the ISC license.

> ISC License
>
> Copyright (c) 2013-2019
Frank Denis <j at pureftpd dot org>
>
> Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

