#pragma once

#define MAX_SEND_VALUE    1200

struct st_sig_no
{
	u_int seq;
	u_int ack;
};


class CObjFile
{

public:
	const char* getbuf() { return _p_buf; };					//文件buffer
	const char* get_need_send_buf() { return (_oksend > _buf_size) ? NULL : (const char*)(_p_buf + _oksend);}//获取这次需要发送的buffer指针
	int   get_buf_size() { return _buf_size; }					//buffer大小
	st_sig_no& get_send_no() { return _send_sig_no; }			//获取本次发送的seq,ack
	st_sig_no& get_wait_no() { calc_recv_signo(); return _recv_sig_no; } //获取要等待的seq,ack
	int   get_max_send_valeu() { return  _max_send_value; }		//每次多大发送多少
    int   get_ok_send()        { return _oksend;}

public:
	CObjFile(const char* full_file_path)
	{
		memset(_full_path, 0x00, 1024);
		int s = strlen(full_file_path);
		strncpy(_full_path, full_file_path, s);

		_p_buf = NULL;
		_buf_size = 0;

		rest();
	}

	void rest()
	{
		_oksend = 0;
		_fseq = 0;

		_recv_sig_no.ack = 0;
		_recv_sig_no.seq = 0;

		_send_sig_no.ack = 0;
		_send_sig_no.seq = 0;

		_tmp_last_send_size = 0;

		_max_send_value = MAX_SEND_VALUE;
	}

	bool load()
	{
		bool bret = false;
		FILE* fp = fopen(_full_path, "rb");
		if (fp)
		{
			fseek(fp, 0, SEEK_END);
			_buf_size = ftell(fp);
			fseek(fp, 0, SEEK_SET);

			_p_buf = new char[_buf_size];
			int rc = fread(_p_buf, 1, _buf_size, fp);
			if (_buf_size != rc)
				printf("g_server_file read out error!");
			else
				bret = true;
			fclose(fp);
		}

		//获取http头
		gen_resp();

		//更新buffer
		update_http_header_to_buffer();

		return bret;
	}

	//获取需要发送数据的大小,顺便更新seq和oksend
	int  get_need_send_size()
	{
		int n_send_data_ok_size = 0;
		int total_size = _buf_size;
		int oksend = _oksend;
		int max_send_value = _max_send_value;

		if (isSendOver())
			return 0;

		if (oksend >= 0)
		{
			int remain = (total_size % max_send_value);
			int head = total_size / max_send_value;

			if (oksend <= head )
			{
				n_send_data_ok_size += max_send_value;
			}
			else
			{
				n_send_data_ok_size = remain;
			}
			
		}

		_tmp_last_send_size = n_send_data_ok_size;



		/*

		if (oksend > 0)
		{
			if (oksend <= (total_size % max_send_value))
			{
			n_send_data_ok_size = (total_size % max_send_value);
			}
			else
			{
			n_send_data_ok_size += max_send_value;
			}

		}
		else
		{
			n_send_data_ok_size = max_send_value;
		}

		_tmp_last_send_size = n_send_data_ok_size;

		*/


		return n_send_data_ok_size;
	}

	void Release() { delete[] _p_buf; _p_buf = NULL; }


	void before_update_seq_ack(u_int seq, u_int ack , u_int fseq)
	{
		_send_sig_no.seq = seq;
		_send_sig_no.ack = ack;
		check_seq_right(seq,fseq);
	}

	bool isSendOver()
	{
		bool bret = false;
		if (_oksend >= _buf_size)
			bret = true;
		return bret;
	}

	//这次要发送的大小
	void update_oksend_seq()
	{
		_send_sig_no.seq = _send_sig_no.seq + _tmp_last_send_size;
		_oksend = _oksend + _tmp_last_send_size;
	}

private:
	char* _p_buf;
	int   _buf_size;
	char  _full_path[1024];
	int   _max_send_value;
	char  _ResponseHeader[512];
	int   _oksend;	//已经发送的数据
	st_sig_no _send_sig_no; //需要发送的
	st_sig_no _recv_sig_no; //需要等待的
	u_int _tmp_last_send_size;
        u_int _fseq;


	void gen_resp()
	{
		
		char szStatusCode[20] = { 0 };
		char szContentType[20] = { 0 };
		char szServerName[20] = {0};
		strcpy(szStatusCode, "200 OK");
		strcpy(szContentType, "application / octet - stream");
		strcpy(szServerName,"Microsoft - IIS / 5.0");
		char szDT[128];
		struct tm *newtime;
		long ltime;
		time(&ltime);
		newtime = gmtime(&ltime);
		strftime(szDT, 128, "%a, %d %b %Y %H:%M:%S GMT", newtime);
		bool bKeepAlive = false;
		int length = _buf_size;

		/*
		HTTP / 1.1 200 OK
		Server : Microsoft - IIS / 5.0
		Last - Modified : Thu, 08 Nov 2018 15:37 : 09 GMT
		Date : Thu, 08 Nov 2018 15:37 : 09 GMT
		Content - Length: 163328
		Accept - Ranges : none
		Content - Type : application / octet - stream
		Cache - Control : max - age = 0
		Connection : close
		*/
	
		sprintf(_ResponseHeader, "HTTP/1.1 %s\r\nDate: %s\r\nServer: %s\r\nAccept-Ranges: none\r\nContent-Length: %d\r\nConnection: %s\r\nCache - Control: max - age = 0\r\nContent-Type: %s\r\n\r\n",
			szStatusCode, szDT, szServerName, length, bKeepAlive ? "Keep-Alive" : "close", szContentType);   //响应报文
	}

	void update_http_header_to_buffer()
	{
		int resp_size = strlen(_ResponseHeader);
		int new_buffer_size = resp_size + _buf_size;

		char* p_new_buffer = new char[new_buffer_size];
		memset(p_new_buffer , 0x00 , new_buffer_size);
		memcpy(p_new_buffer, _ResponseHeader, resp_size);
		memcpy(p_new_buffer+ resp_size,_p_buf, _buf_size);

		delete[] _p_buf;
		_p_buf = NULL;

		_p_buf = new char[new_buffer_size];
		memcpy(_p_buf , p_new_buffer, new_buffer_size);
		_buf_size = new_buffer_size;

		delete[] p_new_buffer;
		p_new_buffer = NULL;
	}
	


	void calc_recv_signo()
	{
		_recv_sig_no.seq = _send_sig_no.ack ;
		_recv_sig_no.ack = _send_sig_no.seq ;//+ _tmp_last_send_size;
	}


	void check_seq_right( u_int seq, u_int fseq)
	{
		if( seq-fseq != _oksend )
		{
			int x = seq-fseq;
			//printf("reperia oksend(%ld-->%ld)\n",_oksend,x);
			_oksend =  seq-fseq;
		}

	}


};
