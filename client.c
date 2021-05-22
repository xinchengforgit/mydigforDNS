#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define BUF_SIZE 1024             //最大字节
#define PORT 53                   //53端口号
#define DFSERVER "192.168.99.186" //不使用@时的默认的dns解析器,本地DNS服务器
//先封装一个DNS头部的结构体,协议头为固定的12字节，结构如下：
typedef struct DNS_HDR
{
    uint16_t ID;
    uint16_t Flags; //比较重要的flags参数 d
    uint16_t Questions;
    uint16_t Answers;
    uint16_t AuthorityRRs;  //认证机构数目（仅响应包里有）
    uint16_t AdditionalRRs; //额外信息数目(同上)
} DNS_HDR;
typedef struct _DNS_QER
{
    uint16_t type;

    uint16_t classes;
} DNS_QER;
int main(int argc, char *argv[])
{
    char def[] = "202.114.0.242";
    if (argc == 3)
    {
        if (argv[2][0] = '@')
        {
            strcpy(def, argv[2] + 1);
            printf("%s", def);
        }
        //如果有 @那么修改默认的查询ip地址
    }
    int servfd, clifd, len = 0, i; //待看
    struct sockaddr_in servaddr;
    int socklen = sizeof(servaddr);

    char buf[BUF_SIZE], buf2[BUF_SIZE];
    char *p;
    DNS_HDR *dnshdr = (DNS_HDR *)buf;                     //将指针强制转换，由于该结构体都是uint16_t，故而不需要考虑字节对齐问题
    DNS_QER *dnsqer = (DNS_QER *)(buf + sizeof(DNS_HDR)); //没啥好说的
    if ((clifd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)     //这一行的错误找了半天
    {
        printf("socket create error\n");
        return -1;
    }
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT); //经典的socket
    // int inet_aton(const char *cp, struct in_addr *inp);,将正常的ip地址转化位in_addr
    // char *inet_ntoa(struct in_addr in); //上述反过来
    //注意包含的头文件 #include<sys/socket.h> #include<netinet/in.h> #include<arpa/inet.h>
    if (inet_aton(def, &servaddr.sin_addr) != 1)
    {
        printf("INVALID IP ADDRESS");
        return -1;
    } //这个是之后要改的
    //ok
    //理一个思维模式,先把这个的bug发现
    memset(buf, 0, BUF_SIZE);
    dnshdr->ID = (uint16_t)1;      //为什么要这样呢因为默认的1并不是2字节
    dnshdr->Flags = htons(0x0100); //没啥好说的就是00000001 00000000,结合dns报文容易得知是递归查询
    dnshdr->Questions = htons(1);  //表示一个询问
    dnshdr->Answers = 0;
    strcpy(buf + sizeof(DNS_HDR) + 1, argv[1]);
    p = buf + sizeof(DNS_HDR) + 1;
    i = 0;
    while (p < (buf + sizeof(DNS_HDR) + 1 + strlen(argv[1])))
    {
        if (*p == '.')
        {
            *(p - i - 1) = i;
            i = 0;
        }
        else
        {
            i++;
        }
        p++;
    }
    *(p - i - 1) = i;
    //这个其实无所谓,因为本来就是0
    dnsqer = (DNS_QER *)(buf + sizeof(DNS_HDR) + 2 + strlen(argv[1]));
    dnsqer->classes = htons(1); //1表示A类型
    dnsqer->type = htons(1);    //查询IP,如果是NS的话,type的值为htons(2)
    len = sendto(clifd, buf, sizeof(DNS_HDR) + sizeof(DNS_QER) + strlen(argv[1]) + 2, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    int len1 = len;
    printf("hello\n");
    i = sizeof(struct sockaddr_in);
    len = recvfrom(clifd, buf2, BUF_SIZE, 0, (struct sockaddr *)&servaddr, &i); //recvfrom可以返回获取报文的字节长度
    if (len < 0)
    {
        perror("recv error");
        return -1;
    }
    char *p1 = buf2 + 2;
    //debug用printf("%u\n", (unsigned char)*(p1 + 3));
    if ((unsigned char)*(p1 + 3) & (15) == 2) //响应报文的后四段,如果是2表示查询失败
    {

        printf("server error");
        return -1;
    }
    p = buf2 + len - 4;
    printf("%s ==> %u.%u.%u.%u\n", argv[1], (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
    //先获取到IP地址,在进行NS查询
    dnsqer->classes = htons(1); //1表示A类型
    dnsqer->type = htons(2);    //再进行查询NS
    len = sendto(clifd, buf, sizeof(DNS_HDR) + sizeof(DNS_QER) + strlen(argv[1]) + 2, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
    i = sizeof(struct sockaddr_in);
    len = recvfrom(clifd, buf2, BUF_SIZE, 0, (struct sockaddr *)&servaddr, &i);
    if (len < 0)
    {
        printf("recverror");
    }
    p = buf2 + len1 + 11; //直接从ANSWERS的length 部分开始
    printf("Alias ==> ");
    // int len3 = (unsigned char)*p;
    // p++;
    // while (p < buf2 + len1 + 11 + len3)
    // {
    //     if ((unsigned char)*p < 'a')
    //     {
    //         printf(".");
    //         int num = (unsigned char)*p;
    //         for (int j = 1; j <= num; j++)
    //         {
    //             if (*p >= 'a' && *p <= 'z')
    //                 printf("%c", *p);
    //             else if ((unsigned char)*(p - 1) == 0xc0)
    //             {
    //                 //表示现在要输出压缩的字段
    //                 int num2 = (unsigned char)*(p - 1);
    //                 char *temp = buf2 + num2;
    //                 while (*temp)
    //                 {
    //                     if (*temp <= 'a' && *temp >= 'z')
    //                     {
    //                         printf("%c", *temp);
    //                         temp++;
    //                     }
    //                     else
    //                     {
    //                         printf(".");
    //                         temp++;
    //                     }
    //                 }
    //             }
    //             p++;
    //         }
    //     }
    // } //现在可以把name字段输出完了应该
    while (*p)
    {

        if ('a' <= *p && *p <= 'z')
        {
            printf("%c", *p);
            p++;
        }
        else if ((unsigned char)*p == 0xc0)
        {
            p++;
            char *temp = buf2 + *p++;
            while (*temp)
            {
                if ('a' <= *temp && *temp <= 'z')
                {
                    printf("%c", *temp);
                    temp++;
                }
                else
                {
                    printf(".");
                    temp++;
                }
            }
            break;
        }
        else
        {
            // printf(".");
            // p++;
            printf(".");

            ++p;
        }
    }
    printf("\nAuthoritive Servers====>\n");
    printf("\n");
    printf("NAME ==> ");
    //通过数数数出来的加减
    while (*p)
    {

        if ('a' <= *p && *p <= 'z')
        {
            printf("%c", *p);
            p++;
        }
        else if ((unsigned char)*p == 0xc0)
        {
            p++;
            char *temp = buf2 + *p++;
            while (*temp)
            {
                if ('a' <= *temp && *temp <= 'z')
                {
                    printf("%c", *temp);
                    temp++;
                }
                else if ((unsigned char)*temp == 0xc0)
                {
                    temp++;
                    char *temp2 = buf2 + *temp++;
                    while (*temp2)
                    {
                        if ('a' <= *temp2 && *temp2 <= 'z')
                        {
                            printf("%c", *temp2);
                            temp2++;
                        }
                        else
                        {
                            printf(".");
                            temp2++;
                        }
                    }
                    break;
                }
                else
                {
                    printf(".");
                    temp++;
                }
            }
            break;
        }
        else
        {
            // printf(".");
            // p++;
            printf(".");

            ++p;
        }
    }
    p += 11;
    printf("\nPrimary name server=====>");
    while (*p)
    {
        if ('a' <= *p && *p <= 'z')
        {
            printf("%c", *p);
            p++;
        }
        else if ((unsigned char)*p == 0xc0)
        {
            p++;
            char *temp = buf2 + *p++;
            while (*temp)
            {
                if ('a' <= *temp && *temp <= 'z')
                {
                    printf("%c", *temp);
                    temp++;
                }
                else if ((unsigned char)*temp == 0xc0)
                {
                    temp++;
                    char *temp2 = buf2 + *temp++;
                    while (*temp2)
                    {
                        if ('a' <= *temp2 && *temp2 <= 'z')
                        {
                            printf("%c", *temp2);
                            temp2++;
                        }
                        else
                        {
                            printf(".");
                            temp2++;
                        }
                    }
                    break;
                }
                else
                {
                    printf(".");
                    temp++;
                }
            }
            break;
        }
        else
        {
            // printf(".");
            // p++;
            printf(".");

            ++p;
        }
    }
    //读取报文时如果时0xc0那么就是就压缩内容
    close(clifd);
}