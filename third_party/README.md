# Third party

Fathom does not vendor [ret-sync](https://github.com/bootleg/ret-sync). That project stays under its own GPL-3 license, and Fathom does not compile or link it.

To use the LLDB plugin with `fathom sync serve`, clone it beside the engine:

```
git clone https://github.com/bootleg/ret-sync.git third_party/ret-sync
```

The checkout is listed in `.gitignore` so it is not committed with Fathom.
