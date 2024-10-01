import r2pipe

if __name__ == "__main__":
    cmdPipe = r2pipe.open("NPP.exe")
    cmdPipe.cmd("aaa")
    cmdPipe.cmd("agCd > output.dot")
    cmdPipe.cmd("!!dot -Tpng -o callgraph.png output.dot")


