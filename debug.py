from libhopper import analysis


# Debug only
if __name__ == "__main__":
    # analysis("./libapi_name.dump", 0x7fffffffdb50, 0x78, 0x555555555228)
    # analysis("./libapi_read.dump", 0x7fffffffdb50, 0x78, 0x555555555266)
    # analysis("./libapi_write.dump", 0x7fffffffdb50, 0x78, 0x55555555527c)
    analysis("./libapi_lotto.dump", 0x7fffffffdb50, 0x78, 0x5555555552a6)
    # analysis("./libapi_exec.dump", 0x7fffffffdb50, 0x78, 0x5555555552b5)