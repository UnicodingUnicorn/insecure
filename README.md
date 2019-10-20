# insecure

A simple login-based webapp that is vulnerable to SQL injection, designed to be compiled into a single portable binary, DB and all. Think DVWA.

Why? Suppose you want to run a small exercise in SQL injection, or test an IDS rule, or something in some network. Suppose that said network is a closed network, or you are not allowed to install your \<insert hipster stack\>, or some other inane red tape reason that makes you want to tie a noose from the stuff to hang the no life bureaucrat who made it up. Suppose you then spend the next 4 hours porting something (i.e. an entire VM) over on a dinky little 2GB flash drive.

Yeah, it's not like I'm speaking from experience or anything. I'm not salty.

## Building

```
# Windows
cargo build --release --target x86_64-pc-windows-gnu
# Linux
cargo build --release --target x86_64-unknown-linux-musl
```

Copy the resulting binary out from `/target` and do whatever.

## Example injects

```
' OR 1=1;--
' UNION SELECT group_concat(username || ':' || password) AS username FROM users;--
```

## Default Data (Table "users")

| username | password  |
| -------- | --------- |
| admin    | P@ssw0rd  |
| User 1   | password1 |
| User 2   | password2 |
| User 3   | password3 |
