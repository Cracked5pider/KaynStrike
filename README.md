
# KaynStrike

A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.

### Thread Start Address spoofing
![Preview](https://pbs.twimg.com/media/FT-k25TXEAEP-gR?format=png&name=900x900)

### Reflective Loader cleanup
![Preview](https://pbs.twimg.com/media/FT-lGMNWIAUWJmt?format=png&name=900x900)

### Proof
![Preview](https://pbs.twimg.com/media/FT-lepmWQAUfNPF?format=png&name=large)

### How to use this
Just load the `KaynStrike.cna` agressor script and build a stageless beacon (tested this as an exe)

### Credits
- [S4ntiagoP](https://twitter.com/s4ntiago_p). Had the idea from one of his [tweets](https://twitter.com/s4ntiago_p/status/1531051845187141640) to free the reflective loader
- [Austin Hudson (aka SecIdiot)](https://twitter.com/ilove2pwn_). Reflective Loader Design & ROP Chain