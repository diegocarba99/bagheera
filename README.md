# Bagheera: Advanced Polymorphic Engine

<img src="https://github.com/diegocarba99/bagheera/blob/8cd7713ef5c70a8abaec8501dcea554f6edf4792/logo-2.png" width="256" align="left" />Advanced polymorphic and infection engine for code and payload encryption and binary infection. 

Developed in `C++`, can be used to award polymorphic features to any piece of text. Code and payloads can be encrypted and decrypted using **Bagheera**.

## Features
- Polymorphic conversion of custom binary payload
- Execution of polymorphic version of binary payload
- ELF file infection with polymorphic version of binary payload using the PT_NOTE to PT_LOAD method

## Usage
You can either download the latest release or build the program yourself using `make`. Bagheera can be operated in two modes: *engine* and *infect*. Both modes support a verbose mode, that gives insightful information about the steps the engine performs.

### *Engine* mode
Convert to polymorphic and execute a binary payload provided to the program.

```bash
$ bagheera -m engine -i /path/to/payload
```

### *Infect* mode
Infect a given ELF binary file with a payload, which will be morphed upon infection.

```bash
$ bagheera -m infect -i /path/to/payload -e /path/to/elf
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/diegocarba99/bagheera or via mail to [diegocarballedamartinez@gmail.com](mailto:diegocarballedamartinez@gmail.com). 

## License

The theme is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
