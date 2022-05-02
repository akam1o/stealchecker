# stealchecker

Checking CPU steal of VM from virtual host

## About stealchecker

CPU steal time is time stolen from VM by the virtual host. This can be seen with commands such as top and vmstat from VM. But the virtual host cannot see it.

Stealchecker calculates the CPU steal of the VM from the virtual host.


The principle is as follows:

1. Collect VM info with the virsh command
2. Collect runqueue wait times from schedstat of vcpu processes
3. Calculate CPU steal from the sum of the runqueue wait times per unit time

## Requirements

Can use the virsh command

## Usage

*CPU steal is not calculated on the first run

```
$ sudo stealcheck check
Domain ID                       %cpu_use      %cpu_steal
instance-00000001                 48.68%           0.78%
instance-00000002                  0.60%           0.02%
instance-00000003                  2.63%           0.23%
instance-00000004                  6.11%           0.86%
instance-00000005                  1.77%           0.10%
instance-00000006                  3.57%           0.07%
instance-00000007                  0.38%           0.01%
instance-00000008                 33.13%           0.88%
instance-00000009                 17.52%           0.05%
instance-0000000a                 26.37%           0.53%
```

Display with domain UUID

```
$sudo stealcheck check --uuid
Domain UUID                                     %cpu_use      %cpu_steal
2ab6a587-a844-4377-b7e2-a9380db6e167              41.09%           0.67%
04170a61-4289-4f77-9b3d-b8b1b366afe3               0.35%           0.02%
a53e6892-94cf-494d-9b68-bc97842f618f               2.99%           0.19%
5cf50394-eefd-4f9b-bf02-2c764fa4bdd7               6.32%           0.47%
d506ca79-8014-423d-b9bd-62f8e1dc63c0               1.74%           0.09%
3bd0f56e-6efb-4dd1-aadd-0d03a84020b9               3.04%           0.11%
4ff26ab3-de16-4564-ba58-9e4fdb364272               0.76%           0.05%
09c135aa-679c-44a5-aead-14444eb8088c              33.09%           1.04%
2a50a61e-4179-4b71-a26f-61901cf23cd1               0.98%           0.02%
1df6befa-af2a-4534-938b-44c933d2b3b6              26.57%           0.61%
```
