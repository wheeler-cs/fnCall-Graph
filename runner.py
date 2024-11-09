import sys
sys.path += ["GraphGeneration"]

import batchProcess


if __name__ == "__main__":
    argv = batchProcess.parseArgv()
    fileList = batchProcess.getFileList(argv.inputdir)
    splitLists = batchProcess.generateSublists(fileList, argv.procnum)
    batchProcess.threadedGeneration(splitLists, argv.procnum)
