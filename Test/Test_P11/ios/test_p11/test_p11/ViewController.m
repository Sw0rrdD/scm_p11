//
//  ViewController.m
//  test_p11
//
//  Created by admin on 2018/3/22.
//  Copyright © 2018年 admin. All rights reserved.
//

#import "ViewController.h"
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "init_card.h"
#include "p11_model_test.h"

#define CHANNEL_INIT_SSL



#define USER_PIN "123456"
#define SO_PIN "012345"
extern int test_functionality(void);

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    CK_RV rv = CKR_OK;
    
    NSString *urlStr = @"http://baidu.com";
    //如果字符串里面含有中文要进行转码
    urlStr = [urlStr stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    //2.创建资源路径
    NSURL *url = [NSURL URLWithString:urlStr];
    //3.创建请求
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    //4.发送请求
    [NSURLConnection sendAsynchronousRequest:request queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
        NSLog(@"%@",data);
    }];
    
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *path = [paths objectAtIndex:0];
    
    
    //删除ssp目录
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if ([fileManager removeItemAtPath:path error:NULL]) {
        NSLog(@"Removed successfully");
    }
    
    NSString* resourcePath = [[NSBundle mainBundle]resourcePath];
    const char* resourcePath_str = [resourcePath UTF8String];
    
    
    const char* p_ssp_path = [path UTF8String];
    printf("ssp_path:%s\n",p_ssp_path);
    
    
    char ssp_path[1024];

    //strcpy(ssp_path, path);
    //strcat(ssp_path,"/");
    
    strcpy(ssp_path, p_ssp_path);
    strcat(ssp_path,"/");
    
    rv = scm_init("12345678", NULL,(char*)ssp_path);
    
    if(rv != 0)
    {
        printf("virtual_card_init failed! ret:%d!\n", (CK_UINT)rv);
    }
    
    /** 测试p11 **/
    //int ret = test_functionality();
    
    //p11_test();
    int ret = p11_model_test();
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
