# Cup of TEA
 
FF14에 사용할 수 있을지도 모르는 프로그램입니다
버튼이 2개 있습니다.

게임을 켠 상태에서 위쪽 버튼을 누르면 뭔가 저장될 지도 모릅니다.
게임을 끈 후 다시 킬 때, 아래 버튼을 누르면 런처를 건너뛰고 게임을 바로 실행해 버릴지도 모릅니다.

이 프로그램의 코드는 누군가 이전에 만들었던 것의 코드에서 가져와,
보안에 조금 더 신경 쓴 형태로 보강했습니다.
당신의 계정 보안과 관련해 더 큰 메리트를 줄 지도 모릅니다.


# Troubleshooting
만약 위쪽 버튼을 눌렀을 때 에러가 발생한다면 아래의 방법을 시도해 보세요.

1. [.NET Frameworkd 4.8.1](https://dotnet.microsoft.com/en-us/download/dotnet-framework/net481) 설치 또는 복구
2. 관리자 권한으로 실행
3. 백신/방화벽 확인
4. WMI Repository 재빌드
- 명령 프롬프트를 관리지 권한으로 엽니다.
- 아래의 명령을 실행합니다.
```
winmgmt /salvagerepository
winmgmt /resetrepository
```
