import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:collection/collection.dart';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:intl/intl.dart';
import 'dart:io';

void main() async {
  final bucket = '';
  final accessKey = '';
  final secretKey = '';
  final region = '';
  final objectKey = '';
  final accountId= '';
  //final filePath= '';

 // final file = File(filePath);
 // final fileLength = await file.length();
  
  final endpoint = accountId+'.r2.cloudflarestorage.com';
  final request = http.Request(
    'GET',
    Uri.parse('https://'+accountId+'.r2.cloudflarestorage.com/'+bucket+'/'+objectKey),
  );
  request.headers['x-amz-content-sha256'] = 'UNSIGNED-PAYLOAD';
  final now = DateTime.now().toUtc();
  final year = now.year.toString().padLeft(4, '0');
  final month = now.month.toString().padLeft(2, '0');
  final day = now.day.toString().padLeft(2, '0');
  final hour = now.hour.toString().padLeft(2, '0');
  final minute = now.minute.toString().padLeft(2, '0');
  final second = now.second.toString().padLeft(2, '0');
  final xAmzDate = '$year$month$day'+ 'T'+ '$hour$minute$second'+'Z';
  print(xAmzDate);
  request.headers['x-amz-content-sha256']='UNSIGNED-PAYLOAD';
  request.headers['x-amz-date'] = xAmzDate;
  
  
 // final stream = file.openRead();
  
 // final bodyBytes = await stream.expand((chunk) => chunk).toList();
  //request.headers['x-amz-content-sha256']= sha256.convert(bodyBytes).toString();
  print('Content Hash is');
  print(request.headers['x-amz-content-sha256']);
  request.headers['Authorization'] = generateSignature(
    endpoint,
    request.method,
    objectKey,
    bucket,
    accessKey,
    secretKey,
    region,
    request.headers['x-amz-date']!,  
    request.headers['x-amz-content-sha256']!,
  );
//  request.bodyBytes = bodyBytes;
 
 // request.headers['Content-Length'] = fileLength.toString();



  print(request);
  print(request.headers);
  final response = await http.Response.fromStream(await request.send());
  print('Response status: ${response.statusCode}');
  print('Response body: ${response.body}');
}

String generateSignature(
  String host,
  String method,
  String objectKey,
  String bucket,
  String accessKey,
  String secretKey,
  String region,
  String amzDate,
  String amzContentSha256,
) {
  final dateSub = amzDate.substring(0, 8);
  final canonicalRequest = '''
$method
/$bucket/$objectKey

host:$host
x-amz-content-sha256:$amzContentSha256
x-amz-date:$amzDate

host;x-amz-content-sha256;x-amz-date
$amzContentSha256''';

  final stringToSign = '''
AWS4-HMAC-SHA256
$amzDate
${amzDate.substring(0, 8)}/$region/s3/aws4_request
${sha256.convert(utf8.encode(canonicalRequest)).toString()}''';
  print(stringToSign);  
  final signingKey = calculateSigningKey(secretKey, amzDate.substring(0, 8), region, 's3');
  final signature = hmacSha256(signingKey, stringToSign);
  final sign = signature.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
  return 'AWS4-HMAC-SHA256 Credential=$accessKey/$dateSub/$region/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=$sign';
}

List<int> calculateSigningKey(String secretKey, String dateStamp, String region, String service) {
  final kSecret = utf8.encode('AWS4$secretKey');
  final kDate = hmacSha256(kSecret, dateStamp);
  final kRegion = hmacSha256(kDate, region);
  final kService = hmacSha256(kRegion, service);
  final kSigning = hmacSha256(kService, 'aws4_request');
  return kSigning;
}

List<int> hmacSha256(List<int> key, String data) {
  final hmac = Hmac(sha256, key);
  return hmac.convert(utf8.encode(data)).bytes;
}
