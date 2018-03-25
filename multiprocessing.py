#!/usr/bin/env python
import multiprocessing

def WorkerProcess(i):
    try:
        print(i)
    except:
        return

pool = multiprocessing.Pool(30)
pool.map(WorkerProcess, [x for x in range(1, 1000)])
pool.terminate()
pool.close()
pool.join()
