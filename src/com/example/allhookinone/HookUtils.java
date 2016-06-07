package com.example.allhookinone;

import java.lang.reflect.Constructor;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public final class HookUtils {
	static{
		System.loadLibrary("onehook");
	}
	
	//这货只有hook拦截，没有hook替换。。
	public static int hookMethod(Member method, String methodsig){
		int result = -1;
		
		if(method instanceof Method || method instanceof Constructor<?>){
			String clsdes = method.getDeclaringClass().getName().replace('.', '/');
			
			String methodname = method.getName();
			
			if(method instanceof Constructor<?>){
				result = hookMethodNative(clsdes, methodname, methodsig, false);
			}else{//for method
				result = hookMethodNative(clsdes, methodname, methodsig, Modifier.isStatic(method.getModifiers()));
			}
		}
		
		return result;
	}
	
	//其实就是got hook
	public static native int elfhook();
	
	//java hook
	private static native int hookMethodNative(String clsdes, String methodname, String methodsig, boolean isstatic);
}
