#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

#include "JavaHook/JavaMethodHook.h"
#include "ELFHook/elfutils.h"
#include "ElfHook/elfhook.h"
#include "common.h"


static inline void get_cstr_from_jstring(JNIEnv* env, jstring jstr, char **out) {
	jboolean iscopy = JNI_TRUE;
	const char *cstr = env->GetStringUTFChars(jstr, &iscopy);
	*out = strdup(cstr);
	env->ReleaseStringUTFChars(jstr, cstr);
}

extern "C" jint Java_com_example_allhookinone_HookUtils_hookMethodNative(JNIEnv *env, jobject thiz, jstring cls, jstring methodname, jstring methodsig, jboolean isstatic){
	HookInfo *info = (HookInfo *)malloc(sizeof(HookInfo));

	get_cstr_from_jstring(env, cls, &info->classDesc);
	get_cstr_from_jstring(env, methodname, &info->methodName);
	get_cstr_from_jstring(env, methodsig, &info->methodSig);

	info->isStaticMethod = isstatic == JNI_TRUE;
	return java_method_hook(env, info);
}
char* (*fgets_old)(char *s, int n, FILE *stream);
char* fgets_new(char *s, int n, FILE *stream)
{


	char *line=fgets_old(s, n, stream);
	if(strstr(line,"TracerPid:")!=NULL)
	{
		LOGE("hook_success fgets_new_fuck_it");

		return "TracerPid:      0\n";
	}else{
		LOGE("hook_success fgets_new");

		return line;
	}

}

int isWin()
{
	char line[1024]={0};
	int win=0;
	FILE* fp=fopen("/proc/self/maps","r");
	if(fp==NULL)
	{
		LOGE("no data");
		return win;
	}
	fgets(line,strlen(line)+1,fp);
	LOGE("%s",line);
	if(strstr("win",line)!=NULL)
	{
		win=1;//win
	}
	fclose(fp);
	return win;
}

void hook_fgets()
{
	LOGD("hook_fgets start isWin=%d \n",isWin());

	elfHook("libonehook.so", "fgets", (void *)fgets_new, (void **)&fgets_old);

	LOGD("hook_fgets end isWin=%d \n",isWin());
}

int (*isWin_old)();
int isWin_new()
{
	LOGD("isWin_new start hook self??");
	//不行啊 got_hook不能hook自己本身的函数，只能hook其他so的导入函数。

	return isWin_old();

}


typedef int (*strlen_fun)(const char *);
strlen_fun old_strlen = NULL;

size_t my_strlen(const char *str){
	LOGI("strlen was called.");
	int len = old_strlen(str);
	return len * 2;
}


strlen_fun global_strlen1 = (strlen_fun)strlen;
strlen_fun global_strlen2 = (strlen_fun)strlen;

#define SHOW(x) LOGI("%s is %d", #x, x)

//其实就是got hook
extern "C" jint Java_com_example_allhookinone_HookUtils_elfhook(JNIEnv *env, jobject thiz){
	const char *str = "helloworld";

	strlen_fun local_strlen1 = (strlen_fun)strlen;
	strlen_fun local_strlen2 = (strlen_fun)strlen;

	int len0 = global_strlen1(str);
	int len1 = global_strlen2(str);
	int len2 = local_strlen1(str);
	int len3 = local_strlen2(str);
	int len4 = strlen(str);
	int len5 = strlen(str);

	LOGI("hook before:");
	SHOW(len0);
	SHOW(len1);
	SHOW(len2);
	SHOW(len3);
	SHOW(len4);
	SHOW(len5);

	elfHook("libonehook.so", "strlen", (void *)my_strlen, (void **)&old_strlen);

	len0 = global_strlen1(str);
	len1 = global_strlen2(str);
	len2 = local_strlen1(str);
	len3 = local_strlen2(str);
	len4 = strlen(str);
	len5 = strlen(str);

	LOGI("hook after:");
	SHOW(len0); //hook global_strlen1 20  got全局hook
	SHOW(len1); //hook global_strlen1 20
	SHOW(len2); //not hook 10  局部变量函数没hook
	SHOW(len3);	//not hook 10
	SHOW(len4); //hook strlen 20
	SHOW(len5); //hook strlen 20
	/*
	06-07 09:48:44.995: I/TTT(12599): len0 is 20
	06-07 09:48:44.995: I/TTT(12599): len1 is 20
	06-07 09:48:44.995: I/TTT(12599): len2 is 10
	06-07 09:48:44.995: I/TTT(12599): len3 is 10
	06-07 09:48:44.995: I/TTT(12599): len4 is 20
	06-07 09:48:44.995: I/TTT(12599): len5 is 20
	 */
	elfHook("libonehook.so", "isWin", (void *)isWin_new, (void **)&isWin_old);

	hook_fgets();

	return 0;
}
