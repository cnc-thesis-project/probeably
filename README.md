# probeably
This is a probe tool we developed for our master thesis.
***It is unfinished, and we leave no guarantees for its usability.***

## Building and installing

```sh
meson build
ninja -C build

sudo meson install
```

# Running
```sh
./build/probeably --config <path to config>
```
  
or run it with systemd:

```sh
systemctl start probeably
```

The probe tool uses a new database file for every restart.
It should be able to separate probing sessions using ids, but we haven't had the time to implement that :relieved:.
