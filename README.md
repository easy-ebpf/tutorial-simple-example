# tutorial-simple-example

## 1. Observe the file structure
- `minimal.bpf.c` :  
  This is the eBPF program we're going to load into the Kernel.

- `minimal.c` :  
  This file is our frontend in the userspace, which is responsible for loading the eBPF program into Kernel.

## 2. Running eBPF program

```bash
make run
```

## 3. Observe the log from the system pipe

```bash
make trace
```

## 4. Try to modify the eBPF program

Try to modify the eBPF program, and compile & run it again.  
Does the output change with your modification?
