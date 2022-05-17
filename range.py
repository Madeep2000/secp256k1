import os

if __name__ == '__main__':
    x = 0
    for i in range(100):
        text = os.popen("./sm2.out").read()
        if (text.find("false")!=-1):
            x = x + 1
    print(x)
