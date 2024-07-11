#include "hy457_crypto.h"


uint8_t getPseudoRandom(){
    uint8_t *myRandomData;
    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0){
            printf("Error while opening urandom\nExiting\n");
            return -1;
        }
    else{
        ssize_t result = read(randomData, myRandomData, sizeof(myRandomData));
        if (result < 0){
            printf("Error while reading from urandom\nExiting\n");
            return -1;
        }
    }
    return *myRandomData;
}

uint8_t* getPseudoRandomBlock(){
    uint8_t* myRandomData=malloc(sizeof(uint8_t)*4);
    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0){
            printf("Error while opening urandom\nExiting\n");
            return NULL;
        }
    else{
        ssize_t result = read(randomData, myRandomData, sizeof(myRandomData));
        if (result < 0){
            printf("Error while reading from urandom\nExiting\n");
            return NULL;
        }
    }
    return myRandomData;
}

uint8_t* otp_encrypt(uint8_t *plaintext, uint8_t *otp_key){
    uint8_t* result=malloc(text_size*sizeof(uint8_t));
    for(int i=0;i<text_size;i++){
        if(plaintext[i]<=47||(plaintext[i]<=64&&plaintext[i]>=58)||
        (plaintext[i]<=96&&plaintext[i]>=91)||plaintext[i]>=123)
            otp_key[i]=0;//add 0 to otp_key for every not supported character

        else 
            otp_key[i]=getPseudoRandom();

        result[i]=plaintext[i]^otp_key[i];
    }
    return result;
}

uint8_t* otp_decrypt(uint8_t *ciphertext, uint8_t *otp_key){
    uint8_t* result=malloc(text_size*sizeof(uint8_t));
    for(int i=0;i<text_size;i++){
        result[i]=ciphertext[i]^otp_key[i];
    }
    return result;
}

uint8_t* caesar_encrypt(uint8_t *plaintext, ushort N){
    uint8_t* result=malloc(text_size*sizeof(uint8_t));
    for(int i=0;i<text_size;i++){
        if(plaintext[i]<=47||(plaintext[i]<=64&&plaintext[i]>=58)||
        (plaintext[i]<=96&&plaintext[i]>=91)||plaintext[i]>=123)
            result[i]=plaintext[i];//ignore the N
        else 
            result[i]=(plaintext[i]+N)%256;
    }
    return result;
}

uint8_t* caesar_decrypt(uint8_t *plaintext, ushort N){
    uint8_t* result=malloc(text_size*sizeof(uint8_t));
    for(int i=0;i<text_size;i++){
       
        if (plaintext[i]-N<0) plaintext[i]+=256;       
        result[i]=(plaintext[i]-N)%256;
        
    }
    return result;
}

unsigned char* playfair_encrypt(unsigned char *plaintext){ 
    for (size_t i = 0; i < strlen(plaintext); i++){
        if (plaintext[i]=='J') plaintext[i]='I';
    } 

    int is_odd=0;
    if (strlen(plaintext)%2==1) is_odd=1;
    unsigned char pairs[strlen(plaintext)/2+is_odd][2];
    //printf("%ld\n",strlen(plaintext));

    for (size_t i = 0; i < strlen(plaintext); i++){
        if(i+1==strlen(plaintext)&&(strlen(plaintext)%2)) {
            //printf("[%c]\n",plaintext[i]);
            pairs[i/2][0]= plaintext[i];
            pairs[i/2][1]='X';}
        else pairs[i/2][i%2]= plaintext[i];     
    }
    for (size_t z = 0; z < strlen(plaintext)/2+is_odd; z++){ 
        if(pairs[z][1]==pairs[z][0]) pairs[z][1]='X';
        //fprintf(stderr,"%c-%c\n",pairs[z][0],pairs[z][1]); 
    }
    int row1,col1,row2,col2;
    //fprintf(stderr,"---------------\n");
  
    for (size_t z = 0; z < strlen(plaintext)/2+is_odd; z++){     
        for(size_t i=0;i<5;i++){
            for(size_t j=0;j<5;j++){
                if(playfair_keymatrix[i][j]==pairs[z][0]){
                    row1=i;
                    col1=j;
                }               
                if(playfair_keymatrix[i][j]==pairs[z][1]){
                    row2=i;
                    col2=j;
                }

            }
        }
        //fprintf(stderr,"%d,%d AND %d,%d\n",row1,col1,row2,col2); 

        if(row1==row2){
            pairs[z][0]=playfair_keymatrix[row1][(col1+1)%5];
            pairs[z][1]=playfair_keymatrix[row2][(col2+1)%5];
        }
        else if(col1==col2){
            pairs[z][0]=playfair_keymatrix[(row1+1)%5][col1];
            pairs[z][1]=playfair_keymatrix[(row2+1)%5][col2];
        }else{    
            //if(row1<row2&&col1<col2){    
               // fprintf(stderr,"%c=%d,%d AND %c=%d,%d\n",playfair_keymatrix[row1,col1],row1,col1,playfair_keymatrix[row2,col2],row2,col2);
                pairs[z][0]=playfair_keymatrix[row1][col2];
                pairs[z][1]=playfair_keymatrix[row2][col1];
            //}
        }
    }
    /*
    fprintf(stderr,"---------------\n");
    for (size_t z = 0; z < strlen(plaintext)/2+is_odd; z++){ 
        fprintf(stderr,"%c-%c\n",pairs[z][0],pairs[z][1]); 
    }*/
    unsigned char* result =malloc((strlen(plaintext)+is_odd+1)*sizeof(unsigned char));
    int count=0;
    for (size_t j = 0; j < strlen(plaintext)/2+is_odd;j++){
        result[count++]=pairs[j][0];
        result[count++]=pairs[j][1];       
    }
    result[count]=0;
    return result;
    
}   

unsigned char* playfair_decrypt(unsigned char *plaintext){

    unsigned char pairs[strlen(plaintext)/2][2];
    //printf("%ld\n",strlen(plaintext));

    for (size_t i = 0; i < strlen(plaintext); i++){
        pairs[i/2][i%2]= plaintext[i];     
    }

    int row1,col1,row2,col2;
    for (size_t z = 0; z < strlen(plaintext)/2; z++){ 
        //fprintf(stderr,"%c-%c\n",pairs[z][0],pairs[z][1]); 
    }
    for (size_t z = 0; z < strlen(plaintext)/2; z++){     
        for(size_t i=0;i<5;i++){
            for(size_t j=0;j<5;j++){
                if(playfair_keymatrix[i][j]==pairs[z][0]){
                    row1=i;
                    col1=j;
                }               
                if(playfair_keymatrix[i][j]==pairs[z][1]){
                    row2=i;
                    col2=j;
                }

            }
        }
        //fprintf(stderr,"%d,%d AND %d,%d\n",row1,col1,row2,col2); 

        if(row1==row2){
            if (col1==0) col1=5;
            if (col2==0) col2=5;
            pairs[z][0]=playfair_keymatrix[row1][(col1-1)%5];
            pairs[z][1]=playfair_keymatrix[row2][(col2-1)%5];
        }
        else if(col1==col2){
            if (row1==0) row1=5;
            if (row2==0) row2=5;
            pairs[z][0]=playfair_keymatrix[(row1-1)%5][col1];
            pairs[z][1]=playfair_keymatrix[(row2-1)%5][col2];
        }else{    
            //if(row1<row2&&col1<col2){    
               // fprintf(stderr,"%c=%d,%d AND %c=%d,%d\n",playfair_keymatrix[row1,col1],row1,col1,playfair_keymatrix[row2,col2],row2,col2);
                pairs[z][0]=playfair_keymatrix[row1][col2];
                pairs[z][1]=playfair_keymatrix[row2][col1];
            //}
        }
    }
    
    //fprintf(stderr,"---------------\n");
    for (size_t z = 0; z < strlen(plaintext)/2; z++){ 
        //fprintf(stderr,"%c-%c\n",pairs[z][0],pairs[z][1]); 
    }
    unsigned char* result =malloc((strlen(plaintext)+1)*sizeof(unsigned char));
    int count=0;
    for (size_t j = 0; j < strlen(plaintext)/2;j++){
        result[count++]=pairs[j][0];
        result[count++]=pairs[j][1];       
    }
    result[count]=0;
    return result;
}

uint8_t * affine_encrypt(uint8_t *plaintext){
    //65->0
    //90->25
    uint8_t valid_count=0;
    for(ssize_t i=0;i<strlen(plaintext);i++){
        if(plaintext[i]>=97&&plaintext[i]<=122) plaintext[i]-=32;//ean einai lowercase convert 
        if(plaintext[i]>=65&&plaintext[i]<=90) valid_count++; //determine xmatrix'es length    
    }
    uint8_t *x_matrix=malloc(sizeof(uint8_t)*(valid_count+1));
    valid_count=0;
    for(ssize_t i=0;i<strlen(plaintext);i++){       
        if(plaintext[i]>=65&&plaintext[i]<=90) x_matrix[valid_count++]=plaintext[i]-65;     // fill to X_matrix
    }
    printf("Proccessed Affine Input :");
    for(ssize_t i=0;i<valid_count;i++){
        printf("%c",x_matrix[i]+65);
        x_matrix[i]=(11*x_matrix[i]+19)%26;
    }
    printf("\nEncrypted Affine Output :");
    for(ssize_t i=0;i<valid_count;i++){
        printf("%c",x_matrix[i]+65);
        //x_matrix[i]+=65;
    }
    printf("\n");
    x_matrix[valid_count]=0;//to \0
    return x_matrix;
}

int MultiplicativeInverse(int a){
    for (int x = 1; x < 27; x++)
        if ((a * x) % 26 == 1) return x;
}

uint8_t * affine_decrypt(uint8_t *ciphertext){
    printf("Decrypted Affine Output :");
    uint8_t *result=malloc(sizeof(uint8_t)*(strlen(ciphertext)+1));
    for(ssize_t i=0;i<strlen(ciphertext);i++){       
        result[i]=ciphertext[i];       
    }
    for(ssize_t i=0;i<strlen(ciphertext);i++){
       // printf("%d:",result[i]);
        if(result[i]-19<0) result[i]+=26;
        result[i]=((MultiplicativeInverse(11) * (result[i] - 19)) % 26);
        //printf("%d:",result[i]);
        printf("%c",result[i]+65);
    }
    result[strlen(ciphertext)]=0;
    printf("\n");
    return result;
}

void initialize_playfair_keymatrix(){
    for(int i=0;i<5;i++){
        for(int j=0;j<5;j++){
            playfair_keymatrix[i][j]=0;
        }
    }
}

void print_playfair_keymatrix(){
    for(int z=0;z<5;z++){
        for(int j=0;j<5;j++){
            printf("%c ",playfair_keymatrix[z][j]);
        }
        printf("\n");
    }
}

void fill_playfair_keymatrix(unsigned char *plaintext){
    int found=0,insert=0,j,z;
    for(int i=0;i<strlen(plaintext);i++){
        if(plaintext[i]<65||plaintext[i]>90){
            printf("Error illegal character as playfair input.\nEXITING\n");
            return;
        }else { 
            if (plaintext[i]=='J') plaintext[i]='I';
            for(z=0;z<5;z++){
                for(j=0;j<5;j++){
                    if(playfair_keymatrix[z][j]==plaintext[i]) {
                        found=1;
                        break;
                    }
                    if(playfair_keymatrix[z][j]==0) {
                        insert=1;
                        break;
                    }
                }
                if(insert&&!found) {
                    playfair_keymatrix[z][j]=plaintext[i];
                    break;
                }
            }
        }         
        found=0;    
        insert=0;      
    }

    unsigned char to_add=65;//A
    for(int i=0;i<5;i++){
        for(int w=0;w<5;w++){
            if(playfair_keymatrix[i][w]==0){
                while(1){
                    for(int z=0;z<5;z++){
                        for(int j=0;j<5;j++){
                            if(playfair_keymatrix[z][j]==to_add) {
                                found=1;
                                break;
                            }     
                        }
                        if(found) break;  
                    }if(found) {                  
                        to_add++;
                        if(to_add==74) to_add++;//J
                        found=0;                                               
                    }else {
                        playfair_keymatrix[i][w]=to_add++; 
                        if(to_add==74) to_add++;//J
                        break; 
                    }
                    
                }              
            }
        }
    }
}

uint8_t* feistel_F(uint8_t* block, uint8_t* key){
    uint8_t* new_block=malloc(sizeof(uint8_t)*4);
    for (ssize_t i=0;i<4;i++){
        new_block[i]=(block[i]*key[i])%(int)(pow((double)(2), (double)(32)));
    }
    return new_block;
}

uint8_t* feistel_encrypt(uint8_t* plaintext){
    uint8_t* left_block=malloc(sizeof(uint8_t)*4);
    uint8_t* right_block=malloc(sizeof(uint8_t)*4);
    uint8_t* tmp_block=malloc(sizeof(uint8_t)*4);
    for (ssize_t j=0;j<4;j++) {//split the text to 2 blocks
        left_block[j]=plaintext[j];
        right_block[j]=plaintext[4+j];
    }

    for (ssize_t i=0;i<8;i++){//loop representing the encryption rounds
  
        for (ssize_t j=0;j<4;j++){//temp right block buffer
            tmp_block[j]=right_block[j];
        } 
        for (ssize_t j=0;j<4;j++){
            left_block[j]=left_block[j]^feistel_F(right_block,feistel_keys[i])[j];
        }
        if(i!=7){
            for (ssize_t j=0;j<4;j++){
                right_block[j]=left_block[j];
            } 
            for (ssize_t j=0;j<4;j++){
                left_block[j]=tmp_block[j];
            }
        }

    }
    uint8_t* result=malloc(sizeof(uint8_t)*8);
    for (ssize_t i=0;i<4;i++){
        result[i]=left_block[i];
        result[4+i]=right_block[i];
    }
    return result;
}

uint8_t* feistel_decrypt(uint8_t* plaintext){
    uint8_t* left_block=malloc(sizeof(uint8_t)*4);
    uint8_t* right_block=malloc(sizeof(uint8_t)*4);
    uint8_t* tmp_block=malloc(sizeof(uint8_t)*4);
    for (ssize_t j=0;j<4;j++) {//split the text to 2 blocks
        left_block[j]=plaintext[j];
        right_block[j]=plaintext[4+j];
    }

    for (ssize_t i=0;i<8;i++){//loop representing the encryption rounds
        for (ssize_t j=0;j<4;j++){//temp right block buffer
            tmp_block[j]=right_block[j];
        } 
        for (ssize_t j=0;j<4;j++){
            left_block[j]=left_block[j]^feistel_F(right_block,feistel_keys[7-i])[j];
        }
        if(i!=7){
            for (ssize_t j=0;j<4;j++){
                right_block[j]=left_block[j];
            } 
            for (ssize_t j=0;j<4;j++){
                left_block[j]=tmp_block[j];
            }
        }
    }
    uint8_t* result=malloc(sizeof(uint8_t)*8);
    for (ssize_t i=0;i<4;i++){
        result[i]=left_block[i];
        result[4+i]=right_block[i];
    }
    return result;
}

void testOTP(char* string){
    char* plaintext=strdup(string);
    text_size=strlen(plaintext);
    
    otp_key=malloc(text_size*sizeof(uint8_t));
    char Msg_buf [3*text_size+1];
    Msg_buf[3*text_size] = 0;
    for(int i = 0; i < text_size; i++){
        sprintf(&Msg_buf[3*i], "%02X ", plaintext[i]);       
    }  
  
    printf("Starting STRING :%s\n",plaintext);
    printf("Starting HEX :0x %s\n",Msg_buf);

    uint8_t* encryptedMsg=otp_encrypt(plaintext,otp_key);
    char encryptedMsg_buf [3*text_size+1];
    encryptedMsg_buf[3*text_size] = 0;
    for(int i = 0; i < text_size; i++){
        sprintf(&encryptedMsg_buf[3*i], "%02X ", encryptedMsg[i]);       
    }  
    
    printf("Encrypted HEX :0x %s\n",encryptedMsg_buf);

    uint8_t* decryptedMsg=otp_decrypt(encryptedMsg,otp_key);
    char decryptedMsg_buf [3*text_size+1];
    decryptedMsg_buf[3*text_size] = 0;
    for(int i = 0; i < text_size; i++){
        sprintf(&decryptedMsg_buf[3*i], "%02X ", decryptedMsg[i]);       
    }  

    printf("Decrypted HEX :0x %s\n",decryptedMsg_buf);
    printf("Decrypted STRING :%s\n",decryptedMsg);
   
}

void testCAESAR(char* string,ushort N){
    ushort caesar_N=N;
    char* plaintext=strdup(string);
    text_size=strlen(plaintext);
    char Msg_buf [3*text_size+1];
    Msg_buf[3*text_size] = 0;
    for(int i = 0; i < text_size; i++){
        sprintf(&Msg_buf[3*i], "%02X ", plaintext[i]);       
    }  
    printf("Starting STRING :%s\n",plaintext);
    printf("Starting HEX :0x %s\n",Msg_buf);

    uint8_t* encryptedMsg=caesar_encrypt(plaintext,caesar_N);
    char encryptedMsg_buf [3*text_size+1];
    encryptedMsg_buf[3*text_size] = 0;
    for(int i = 0; i < text_size; i++){
        sprintf(&encryptedMsg_buf[3*i], "%02X ", encryptedMsg[i]);       
    }   
    printf("Encrypted HEX :0x %s\n",encryptedMsg_buf);
    uint8_t* decryptedMsg=caesar_decrypt(encryptedMsg,caesar_N);
    char decryptedMsg_buf [3*text_size+1];
    decryptedMsg_buf[3*text_size] = 0;
    for(int i = 0; i < text_size; i++){
        sprintf(&decryptedMsg_buf[3*i], "%02X ", decryptedMsg[i]);       
    }  
    printf("Decrypted HEX :0x %s\n",decryptedMsg_buf);
    printf("Decrypted STRING :%s\n",decryptedMsg);

}

void testPLAYFAIR(char* string1,char* string2){
    char* key_string=strdup(string1);
    char* plaintext=strdup(string2);
    initialize_playfair_keymatrix();
    fill_playfair_keymatrix(key_string);
    print_playfair_keymatrix();
    printf("STARTING STRING :%s\n",string2);
    printf("ENCRYPTED STRING :%s\n",playfair_encrypt(plaintext));
    printf("DECRYPTED STRING :%s\n",playfair_decrypt(playfair_encrypt(plaintext)));
}

void testAFFINE(char* string){
    char* plaintext=strdup(string);
    affine_decrypt(affine_encrypt(plaintext));
}

void testFEISTEL(char* string){

    //filling the keys array
    for (ssize_t i=0;i<8;i++){
        memcpy(feistel_keys[i],getPseudoRandomBlock(),4);
    }

    char* feistel_string=strdup(string);
    
    //padding
    int padd_bytes=(8-strlen(feistel_string)%8);
    if (padd_bytes==8) padd_bytes=0;
    char* padded_feistel_string=malloc(sizeof(char)*strlen(feistel_string)+padd_bytes);
    for(int i = 0; i < strlen(padded_feistel_string)+padd_bytes; i++){ 
        padded_feistel_string[i]=0;
    }   
    memcpy(padded_feistel_string,feistel_string,strlen(feistel_string));
    //padding_end
    
    text_size=strlen(feistel_string)+padd_bytes;
    char Msg_buf [3*text_size+1];
    Msg_buf[3*text_size] = 0;
    for(int i = 0; i < text_size; i++){
        sprintf(&Msg_buf[3*i], "%02X ", padded_feistel_string[i]);       
    }  
    printf("Starting STRING :%s\n",padded_feistel_string);
    printf("Starting HEX :0x %s\n",Msg_buf);

    char encryptedMsg_buf [3*text_size+1];
    uint8_t* encryptedMsg;
    encryptedMsg_buf[3*text_size] = 0;
    //////////////////////////////////////////
    char decryptedMsg_buf [3*text_size+1];
    uint8_t* decryptedMsg;
    decryptedMsg_buf[3*text_size] = 0;
    //////////////////////////////////////////
    char* decryptedString=malloc(text_size*sizeof(char));
    for(int i = 0; i <text_size/8 ; i++){// i=0,i=1
        //printf("ENCRYPRING -->%s\n",i*8+padded_feistel_string);
        encryptedMsg=feistel_encrypt(i*8+padded_feistel_string);
        for(int j = 0; j < 8; j++){
            sprintf(&encryptedMsg_buf[i*8*3+3*j], "%02X ", encryptedMsg[j]);       
        }       
        decryptedMsg=feistel_decrypt(encryptedMsg);
        for(int j = 0; j < 8; j++){
            decryptedString[8*i+j]=decryptedMsg[j];
            sprintf(&decryptedMsg_buf[i*8*3+3*j], "%02X ", decryptedMsg[j]);       
        }    
    }

    printf("Encrypted HEX :0x %s\n",encryptedMsg_buf);
    printf("Decrypted HEX :0x %s\n",decryptedMsg_buf);
    printf("Decrypted STRING :%s\n",decryptedString);

}
