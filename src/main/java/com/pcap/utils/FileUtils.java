package com.pcap.utils;

import java.io.*;


public class FileUtils {
	
	private FileUtils(){}
	

	public static boolean writeLineToFile(String line, File file, boolean append){
		boolean flag = true;
		try {
			FileWriter fw = new FileWriter(file, append);
			fw.write(line + "\n");
			fw.flush();
			fw.close();
		} catch (IOException e) {
			e.printStackTrace();
			flag = false;
		}
		
		return flag;
	}
	

	public static boolean writeLineToFile(String line, String filepath, boolean append){
		File file = new File(filepath);
		return writeLineToFile(line, file, append);
	}
	

	public static boolean writeLinesToFile(String[] lines, String filepath, boolean append){
		boolean flag = true;
		try {
			File file = new File(filepath);
			FileWriter fw = new FileWriter(file, append);
			for(String line : lines){
				line += "\n";
				fw.write(line);
			}
			fw.flush();
			fw.close();
		} catch (IOException e) {
			e.printStackTrace();
			flag = false;
		}
		
		return flag;
	}
	

	public static boolean createDir(String dirpath){
		boolean flag = false;
		File file = new File(dirpath);
		if(!file.exists()){
			file.mkdirs();
			flag = true;
		} 
		
		return flag;
	}
	

	public static boolean deleteFile(String filepath){
		boolean flag = false;
		File file = new File(filepath);

		if(file.isFile() && file.exists()){
			file.delete();
			flag = true;
		}
		return flag;
	}
	

	private static boolean deleteDirectory(String path){
		boolean flag = false;


		if(!path.endsWith(File.separator)){
			path = path + File.separator;
		}
		File dirFile = new File(path);


		if(!dirFile.exists() || !dirFile.isDirectory()){
			return false;
		}
		flag = true;


		File[] files = dirFile.listFiles();
		for(int i = 0; i < files.length; i ++){

			if(files[i].isFile()){
				flag = deleteFile(files[i].getAbsolutePath());
				if(!flag){
					break;
				}
			} else{
				flag = deleteDirectory(files[i].getAbsolutePath());
				if(!flag){
					break;
				}
			}
		}
		if(!flag){
			return false;
		}


		if(dirFile.delete()){
			return true;
		} else{
			return false;
		}

	}
	

	public static boolean deleteFolder(String path){
		boolean flag = false;
		File file = new File(path);

		if(!file.exists()){
			return flag;
		} else{

			if(file.isFile()){
				return deleteFile(path);
			} else{
				return deleteDirectory(path);
			}
		}
	}
	

	public static void closeStream(InputStream is, OutputStream os) {
		if(is != null){
			try {
				is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		if(os != null){
			try {
				os.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	

	public static void openWindow(String path){
		Runtime runtime = Runtime.getRuntime();
		try {
			Process process = runtime.exec("cmd /c start explorer " + path);
			int exitCode = process.waitFor();
			if(exitCode == 0){
				// success
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
	

	public static void createEmpFile (String pathname) {
		File file = new File(pathname);
		if (file.exists()) {
			deleteFile(pathname);
		}
		
		try {
			file.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	

	public static boolean isFileEmpty(File file) {
		if (file == null || file.length() < 0) {
			return false;
		} else {
			return true;
		}
	}
	
}
