from libhopper import analysis


# Debug only
if __name__ == "__main__":
    struct_addr = 0x7ffcacf45f30
    # analysis("./libapi_name", struct_addr, 0x78, 0x555555555228)
    # analysis("./libapi_read", struct_addr, 0x78, 0x555555555266)
    # analysis("./libapi_write", struct_addr, 0x78, 0x55555555527c)
    # analysis("./libapi_lotto", struct_addr, 0x78, 0x5555555552a6)
    analysis("./libapi_exec", struct_addr, 0x78, 0x556eb36a02b5)
