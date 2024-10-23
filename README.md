# TEE workload spec sample

## Build and run

To build and run the C program:

```bash
make
./tls_test
```

## Analysis
```bash
valgrind --tool=massif --detailed-freq=1 --stacks=yes --time-unit=B ./tls_test
ms_print massif.out.* > massif_report.txt
```