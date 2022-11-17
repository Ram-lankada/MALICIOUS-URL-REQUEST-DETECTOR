from django.http import HttpResponse
from django.shortcuts import render 
import pickle
import joblib 
import numpy as np
import pandas as pd 
from django.contrib import messages


def url(request) :
    if request.method == 'POST' :         
        if request.POST["urlname"] : 
            
                # LOADING MODELS 
                
                lr_model = pickle.load(open("lr_model.pkl", "rb")) 
                mnb_model = pickle.load(open("mnb_model.pkl", "rb")) 
                # rf_classifier = pickle.load(open("tfidf_2grams_randomforest.p", "rb")) 
                # svc_model = joblib.load(open("predictor.joblib", "rb")) 
                
                # NOT TRAINED MODELS 
                xgb_classifier = pickle.load(open("xgb_classifier.pkl", "rb")) 
                ada_classifier = pickle.load(open("ada_classifier.pkl", "rb")) 
                sgd_classifier = pickle.load(open("sgd_classifier.pkl", "rb")) 
                lr_classifier = pickle.load(open("lr_classifier.pkl", "rb")) 
                rf_classifier = pickle.load(open("rf_classifier.pkl", "rb")) 
                svm_classifier = pickle.load(open("svm_classifier.pkl", "rb")) 
                dt_classifier = pickle.load(open("dt_classifier.pkl", "rb")) 
                mnb_classifier = pickle.load(open("mnb_classifier.pkl", "rb")) 
                
                pickle.dump(xgb_classifier,open("xgb_classifier_cv_2.pkl","wb"))
                pickle.dump(ada_classifier,open("ada_classifier_cv_2.pkl","wb"))
                pickle.dump(sgd_classifier,open("sgd_classifier_cv_2.pkl","wb"))
                pickle.dump(lr_classifier,open("lr_classifier_cv_2.pkl","wb"))
                pickle.dump(rf_classifier,open("rf_classifier_cv_2.pkl","wb"))
                pickle.dump(svm_classifier,open("svm_classifier_cv_2.pkl","wb"))
                pickle.dump(dt_classifier,open("dt_classifier_cv_2.pkl","wb"))
                pickle.dump(mnb_classifier,open("mnb_classifier_cv_2.pkl","wb"))
                
                pickle.dump(xgb_classifier,open("xgb_classifier_cv_3.pkl","wb"))
                pickle.dump(ada_classifier,open("ada_classifier_cv_3.pkl","wb"))
                pickle.dump(sgd_classifier,open("sgd_classifier_cv_3.pkl","wb"))
                pickle.dump(lr_classifier,open("lr_classifier_cv_3.pkl","wb"))
                pickle.dump(rf_classifier,open("rf_classifier_cv_3.pkl","wb"))
                pickle.dump(svm_classifier,open("svm_classifier_cv_3.pkl","wb"))
                pickle.dump(dt_classifier,open("dt_classifier_cv_3.pkl","wb"))
                pickle.dump(mnb_classifier,open("mnb_classifier_cv_3.pkl","wb"))
                
                # COUNT VECTORIZER N GRAM MODELS 

                
                # TF-IDF VECTORIZER N GRAM MODELS 
                pickle.dump(xgb_classifier,open("xgb_classifier_tf_1.pkl","wb"))
                pickle.dump(ada_classifier,open("ada_classifier_tf_1.pkl","wb"))
                pickle.dump(sgd_classifier,open("sgd_classifier_tf_1.pkl","wb"))
                pickle.dump(lr_classifier,open("lr_classifier_tf_1.pkl","wb"))
                pickle.dump(rf_classifier,open("rf_classifier_tf_1.pkl","wb"))
                pickle.dump(svm_classifier,open("svm_classifier_tf_1.pkl","wb"))
                pickle.dump(dt_classifier,open("dt_classifier_tf_1.pkl","wb"))
                pickle.dump(mnb_classifier,open("mnb_classifier_tf_1.pkl","wb"))
                
                pickle.dump(xgb_classifier,open("xgb_classifier_tf_2.pkl","wb"))
                pickle.dump(ada_classifier,open("ada_classifier_tf_2.pkl","wb"))
                pickle.dump(sgd_classifier,open("sgd_classifier_tf_2.pkl","wb"))
                pickle.dump(lr_classifier,open("lr_classifier_tf_2.pkl","wb"))
                pickle.dump(rf_classifier,open("rf_classifier_tf_2.pkl","wb"))
                pickle.dump(svm_classifier,open("svm_classifier_tf_2.pkl","wb"))
                pickle.dump(dt_classifier,open("dt_classifier_tf_2.pkl","wb"))
                pickle.dump(mnb_classifier,open("mnb_classifier_tf_2.pkl","wb"))
                
                pickle.dump(xgb_classifier,open("xgb_classifier_tf_3.pkl","wb"))
                pickle.dump(ada_classifier,open("ada_classifier_tf_3.pkl","wb"))
                pickle.dump(sgd_classifier,open("sgd_classifier_tf_3.pkl","wb"))
                pickle.dump(lr_classifier,open("lr_classifier_tf_3.pkl","wb"))
                pickle.dump(rf_classifier,open("rf_classifier_tf_3.pkl","wb"))
                pickle.dump(svm_classifier,open("svm_classifier_tf_3.pkl","wb"))
                pickle.dump(dt_classifier,open("dt_classifier_tf_3.pkl","wb"))
                pickle.dump(mnb_classifier,open("mnb_classifier_tf_3.pkl","wb"))
                
                # APPENDING URLS TO PAYLOAD LIST 
                
                payload = [] 
                payload.append(request.POST["urlname"]) 
                print( payload ) 
                
                # FUNCITONS FOR PREDICTING 
                
                # Random forest classifier 
                '''
                def injection_test(input):
                    variables = input.split('&')
                    values = [ variable.split('=')[1] for variable in variables]
                    print(values)
                    return 'MALICIOUS' if rf_classifier.predict(values).sum() > 0 else 'NOT_MALICIOUS'
                '''
                
                # XGB Classifier 
                sql_keywords = pd.read_csv('https://trello-attachments.s3.amazonaws.com/5ed2d4107c349c221194b608/5ed2d453f0e5a45bcd8cf16c/435e639346787ce2b495a16e9f690ef5/SQLKeywords.txt', index_col=False)
                js_keywords = pd.read_csv("https://trello-attachments.s3.amazonaws.com/5ed2d4107c349c221194b608/5ed2d453f0e5a45bcd8cf16c/dedc7eb9846a30c252cd950a0e2153d9/JavascriptKeywords.txt",index_col=False)
                
                def ret_features(payload) : 
                    features = {} 
                    payload = str(payload)
                    features['length'] = len(payload)
                    features['non-printable'] = len([1 for letter in payload if letter not in str('printable')])
                    features['punctuation'] = len([1 for letter in payload if letter in str('punctuation')])
                    features['min-byte'] = min(bytearray(payload,'utf-8'))
                    features['max-byte'] = max(bytearray(payload,'utf-8'))
                    features['mean-byte'] = np.mean(bytearray(payload,'utf-8'))
                    features['std-byte'] = np.std(bytearray(payload,'utf-8'))
                    features['distinct-byte'] = len(set(bytearray(payload,'utf-8')))
                    features['sql-keywords'] = len([1 for keyword in sql_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
                    features['js-keywords'] = len([1 for keyword in js_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
                    #payload_df = pd.DataFrame(data=features,index=[0],columns=independent_variables)
                    
                    # Have not returned the features 
                    return(features) 
                    
                
                def predict(payload , select ) : 
                    features = ret_features(payload) 
                    print("features:",features) 
                    
                    # Here the dataframe is two attribute indexed data structure it has to be indexed individually.
                    match select : 
                        case 0 :     
                            payload_df = pd.DataFrame(features,index=[0])
                            result = xgb_classifier.predict(payload_df)
                        case 1 : 
                            payload_df = pd.DataFrame(features,index=[1])
                            result = ada_classifier.predict(payload_df)
                        case 2 :
                            payload_df = pd.DataFrame(features,index=[2])
                            result = sgd_classifier.predict(payload_df)
                        case 3 :
                            payload_df = pd.DataFrame(features,index=[3])
                            result = lr_classifier.predict(payload_df)
                        case 4 :         
                            payload_df = pd.DataFrame(features,index=[4])                   
                            result = rf_classifier.predict(payload_df)
                        case 5 :
                            payload_df = pd.DataFrame(features,index=[5])
                            result = svm_classifier.predict(payload_df)
                        case 6 :
                            payload_df = pd.DataFrame(features,index=[6])
                            result = dt_classifier.predict(payload_df)
                        case 7 :
                            payload_df = pd.DataFrame(features,index=[7])
                            result = mnb_classifier.predict(payload_df)


                    print( result ) 
                    print("----------------------------------")
                    
                    if result == [1] : 
                        return("bad")
                    elif(result == [0]):
                        return("good") 
                    
                    
                # PREDICTION 
                
                lr = lr_model.predict(payload) 
                mnb = mnb_model.predict(payload) 
                # xgb = xgb_classifier.predict(payload)  
                # rf  = injection_test(payload) 
                # svc = svc_model.predict(payload)
                
                # NT MODEL PREDICTIONS 
                xgb_FE = predict(payload , 0 ) 
                ada_FE = predict(payload , 1 ) 
                sgd_FE = predict(payload , 2 )
                lr_FE = predict(payload , 3 ) 
                rf_FE = predict(payload , 4 ) 
                svm_FE = predict(payload , 5 ) 
                dt_FE = predict(payload , 6 ) 
                mnb_FE = predict(payload , 7 ) 
                
                
                # xgb_NT = NT_predict(payload , 0 ) 
                # ada_NT = NT_predict(payload , 1 ) 
                # sgd_NT = NT_predict(payload , 2 ) 
                # lr_NT = NT_predict(payload , 3 ) 
                # rf_NT = NT_predict(payload , 4 ) 
                # svm_NT = NT_predict(payload , 5 ) 
                # dt_NT = NT_predict(payload , 6 ) 
                # mnb_NT = NT_predict(payload , 7 ) 

                context={
                    "lr":lr , 
                    "mnb": mnb,
                    # "rf" : rf, 
                    # "svc" : svc 
                    
                    # NT PREDICTS 
                    "xgb_FE" : xgb_FE, 
                    "ada_FE" : ada_FE, 
                    "sgd_FE" : sgd_FE,
                    "lr_FE" : lr_FE, 
                    "rf_FE" : rf_FE,  
                    "svm_FE" : svm_FE, 
                    "dt_FE" : dt_FE, 
                    "mnb_FE" : mnb_FE
                    
                    # 1 GRAM CV PREDICTS 
                    "xgb_CV1" : xgb_CV1, 
                    "ada_CV1" : ada_CV1, 
                    "sgd_CV1" : sgd_CV1,
                    "lr_CV1" : lr_CV1, 
                    "rf_CV1" : rf_CV1,  
                    "svm_CV1" : svm_CV1, 
                    "dt_CV1" : dt_CV1, 
                    "mnb_CV1" : mnb_CV1
                    # 2 GRAM CV PREDICTS
                    "xgb_CV2" : xgb_CV2, 
                    "ada_CV2" : ada_CV2, 
                    "sgd_CV2" : sgd_CV2,
                    "lr_CV2" : lr_CV2, 
                    "rf_CV2" : rf_CV2,  
                    "svm_CV2" : svm_CV2, 
                    "dt_CV2" : dt_CV2, 
                    "mnb_CV2" : mnb_CV2 
                    # 3 GRAM CV PREDICTS
                    
                    # 1 GRAM TF-IDF PREDICTS  
                    "xgb_TF1" : xgb_TF1, 
                    "ada_TF1" : ada_TF1, 
                    "sgd_TF1" : sgd_TF1,
                    "lr_TF1" : lr_TF1, 
                    "rf_TF1" : rf_TF1,  
                    "svm_TF1" : svm_TF1, 
                    "dt_TF1" : dt_TF1, 
                    "mnb_TF1" : mnb_TF1
                    # 2 GRAM TF-IDF PREDICTS
                    "xgb_TF2" : xgb_TF2, 
                    "ada_TF2" : ada_TF2, 
                    "sgd_TF2" : sgd_TF2,
                    "lr_TF2" : lr_TF2, 
                    "rf_TF2" : rf_TF2,  
                    "svm_TF2" : svm_TF2, 
                    "dt_TF2" : dt_TF2, 
                    "mnb_TF2" : mnb_TF2  
                    # 3 GRAM TF-IDF PREDICTS  
                }
                
                return render(request, "index.html" ,context)
        else : 
            messages.MessageFailure(request, 'Subscription Unsuccessful')
            return render ( request , 'index.html')
    else : 
        return render ( request , 'index.html')
# def result(request) : 
#     lr_model = pickle.load("lr_model.pkl")
#     mnb_model = pickle.load("mnb_model.pkl")
    
#     payload = [] 
#     payload.append(request.GET['url'])
#     print(payload) 
    
#     lr = lr_model.predict([payload]) 
#     mnb = mnb_model.predict([payload]) 
    
#     return render(request, "index.html" , {'lr':lr , 'mnb': mnb})
    
    # load a .pkl file 
    # 