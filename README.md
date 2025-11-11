# sim-net
Spin up network environments and simulate attackers

## Local Development

### Test Parser

Get more information on how to use
```bash
python3 ndl_parser/ndl_parser.py --help
```
Should output no errors or warnings
```bash
python3 ndl_parser/ndl_parser.py tests/test1_valid.ndl
```

Should report invalid references
```bash
python3 ndl_parser/ndl_parser.py tests/test3_references.ndl
```
