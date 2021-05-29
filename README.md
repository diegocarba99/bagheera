# Bagheera: Advanced Polymorphic Engine

**Bagheera** is an advanced polymorphic engine for code and payload encryption. 

Developed in `C++`, can be used to award polymorphic features to any piece of text. Code and payloads can be encrypted and decrypted using **Bagheera**.

## TODO
- [x] Add `JitRuntime` and `CodeHolder` variables if basic code doesnt work. Examples in AsmJit documentation webpage.  
- [x] Make it compile for the first time

## Advanced features

Some of  Bagheera's features are the following:

- Code polymorphism
- White noise addition in random places
- Equivalent instructions selected at random. For example, we can do `add` or `neg` and then `sub`. Have a large set of equivalent instructions and select at random using (maybe) this [algo](https://en.wikipedia.org/wiki/Multiply-with-carry_pseudorandom_number_generator)
- The above point can be merged with random execution branches that perform the same job and converge in the same place.
- Changes and randomization of calling convention. 
- Random jumps to un-linearize the execution.
- Multilayer encryption **???**


## Interesting readings

- https://link.springer.com/content/pdf/10.1007/s11416-008-0095-z.pdf
- https://vx-underground.org/papers/VXUG/VxHeavenPdfs/Advanced%20Polymorphic%20Techniques.pdf
- https://books.google.es/books?hl=es&lr=&id=XE-ddYF6uhYC&oi=fnd&pg=PT27&ots=GiFPjuRTL2&sig=1TMH8fckD4Bt3rMX5gDuWnl_3S8&redir_esc=y#v=onepage&q&f=false
- https://link.springer.com/article/10.1007/s11416-008-0095-z
- https://www.lastline.com/blog/history-of-malware-its-evolution-and-impact/
- https://blog.devolutions.net/2019/04/a-history-of-major-computer-viruses-from-the-1970s-to-the-present
- https://www.sentrian.com.au/blog/a-short-history-of-computer-viruses
- http://index-of.es/Viruses/T/The%20Art%20of%20Computer%20Virus%20Research%20and%20Defense.pdf
- https://arxiv.org/pdf/1104.1070.pdf
- https://www.alchemistowl.org/pocorgtfo/pocorgtfo20.pdf
- http://index-of.es/Varios-2/Learning%20Linux%20Binary%20Analysis.pdf
- file:///home/diego/ehu/tfg/elf-basics/elf.pdf
- https://github.com/Binject/binjection/blob/master/bj/inject_elf.go
- https://link.springer.com/content/pdf/10.1007/s11416-006-0028-7.pdf
- https://migeel.sk/blog/2007/08/02/advanced-self-modifying-code/
- https://hexterisk.github.io/blog/posts/2020/03/19/simple-code-injection-techniques-for-elf/
